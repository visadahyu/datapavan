//! The server name an app sends in the first message of a TLS connection, the `ClientHello`'s
//! `server_name` extension (RFC 8446 4.1.2, RFC 6066 3), read from the start of the app's byte stream
//! (W3). Nothing is decrypted: the `ClientHello` is sent in the clear. QUIC carries the same message in
//! its CRYPTO frames ([`crate::quic`]), read here once put together.
//!
//! With Encrypted Client Hello (ECH, the `encrypted_client_hello` extension) the name read is the
//! outer one: a provider's public name if the real name is hidden, or the real name if the extension is
//! only GREASE, as Chrome sends when it has no ECH configuration. The two look the same by design; the
//! engine tells them apart by the public names it saw in DNS answers.
//!
//! The bytes come from any app, so nothing here may panic or read outside the slice
//! (`fuzz_targets/tls.rs`).

/// The most bytes of a stream looked at before giving up: a `ClientHello` with post-quantum key shares
/// spans more than one TCP segment, but fits in this.
pub const MAX_HELLO: usize = 16 * 1024;

/// The `extension_type` of `encrypted_client_hello`.
const ECH: usize = 0xfe0d;

/// What a `ClientHello` says about its server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// The server name, in lower case: with ECH, the outer one.
    pub name: String,
    /// Whether the hello offers ECH: a real one or GREASE.
    pub ech: bool,
}

/// What the start of a stream says about its server name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerName {
    /// The hello, with its name.
    Found(Hello),
    /// The stream is TLS but names no server, or it is not TLS at all.
    None,
    /// More bytes are needed to tell.
    Incomplete,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at.checked_add(1)?)?,
    ])))
}

/// Reads the server name from the start of a stream, which may still be incomplete.
#[must_use]
pub fn server_name(stream: &[u8]) -> ServerName {
    // A TLS record: handshake (22), a 1.x version, its length.
    match stream {
        [] => return ServerName::Incomplete,
        [22, ..] => {}
        _ => return ServerName::None,
    }
    if stream.len() < 5 {
        return ServerName::Incomplete;
    }
    if stream[1] != 3 {
        return ServerName::None;
    }
    // The handshake message may span several records; join their bodies.
    let mut handshake = Vec::new();
    let mut at = 0;
    while at + 5 <= stream.len() && handshake.len() < MAX_HELLO {
        if stream[at] != 22 || stream[at + 1] != 3 {
            return ServerName::None;
        }
        let length = u16_at(stream, at + 3).unwrap_or(0);
        let end = at + 5 + length;
        let Some(body) = stream.get(at + 5..end.min(stream.len())) else {
            return ServerName::None;
        };
        handshake.extend_from_slice(body);
        if end > stream.len() {
            break;
        }
        at = end;
        if hello_length(&handshake).is_some_and(|needed| handshake.len() >= needed) {
            break;
        }
    }
    from_handshake(&handshake)
}

/// Reads the server name from the start of a stream of handshake messages, which may still be
/// incomplete: TLS's record bodies joined, or QUIC's CRYPTO frames in order.
#[must_use]
pub fn from_handshake(handshake: &[u8]) -> ServerName {
    match hello_length(handshake) {
        _ if handshake.len() < 4 => ServerName::Incomplete,
        None => ServerName::None,
        Some(needed) if handshake.len() < needed => {
            if needed > MAX_HELLO {
                ServerName::None
            } else {
                ServerName::Incomplete
            }
        }
        Some(needed) => {
            client_hello(&handshake[4..needed]).map_or(ServerName::None, ServerName::Found)
        }
    }
}

/// The length of a `ClientHello` handshake message, header included, or `None` if it is another message.
fn hello_length(handshake: &[u8]) -> Option<usize> {
    if handshake.len() < 4 {
        return Some(4);
    }
    if handshake[0] != 1 {
        return None;
    }
    let length = usize::from(handshake[1]) << 16
        | usize::from(handshake[2]) << 8
        | usize::from(handshake[3]);
    Some(4 + length)
}

/// The `host_name` of the `server_name` extension of a `ClientHello` body, and whether it offers ECH.
fn client_hello(hello: &[u8]) -> Option<Hello> {
    // Version (2) and random (32), then the session id, cipher suites and compression methods.
    let mut at = 34;
    at += 1 + usize::from(*hello.get(at)?);
    at += 2 + u16_at(hello, at)?;
    at += 1 + usize::from(*hello.get(at)?);
    let extensions_end = at.checked_add(2 + u16_at(hello, at)?)?;
    at += 2;
    if extensions_end > hello.len() {
        return None;
    }
    let mut name = None;
    let mut ech = false;
    while at + 4 <= extensions_end {
        let kind = u16_at(hello, at)?;
        let length = u16_at(hello, at + 2)?;
        let data = hello.get(at + 4..at + 4 + length)?;
        at += 4 + length;
        match kind {
            // server_name: a list, each entry a type (0: host_name) and a name. Only the first counts.
            0 if name.is_none() => {
                let list_end = 2 + u16_at(data, 0)?;
                let mut entry = 2;
                while entry + 3 <= list_end.min(data.len()) {
                    let name_length = u16_at(data, entry + 1)?;
                    let host = data.get(entry + 3..entry + 3 + name_length)?;
                    if data[entry] == 0 {
                        name = Some(valid_name(host)?);
                        break;
                    }
                    entry += 3 + name_length;
                }
            }
            // An outer ECHClientHello starts with type 0; an inner one (1) is never sent in the clear.
            ECH => ech = data.first() == Some(&0),
            _ => {}
        }
    }
    Some(Hello { name: name?, ech })
}

/// A host name of printable ASCII without spaces, in lower case.
pub(crate) fn valid_name(name: &[u8]) -> Option<String> {
    if name.is_empty() || name.len() > 253 || !name.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    Some(
        name.iter()
            .map(|b| char::from(b.to_ascii_lowercase()))
            .collect(),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal `ClientHello` handshake message for `name`, with the extension after another one, and
    /// an outer ECH extension after it if `ech`.
    pub(crate) fn handshake(name: &str, ech: bool) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        let mut extensions = vec![0, 43, 0, 3, 2, 3, 4];
        let entry_length = u16::try_from(name.len()).unwrap_or(0);
        extensions.extend_from_slice(&[0, 0]);
        extensions.extend_from_slice(&(entry_length + 5).to_be_bytes());
        extensions.extend_from_slice(&(entry_length + 3).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&entry_length.to_be_bytes());
        extensions.extend_from_slice(name.as_bytes());
        if ech {
            // Type outer, a cipher suite, config id, an empty enc and a short payload, as GREASE has.
            extensions.extend_from_slice(&[0xfe, 0x0d, 0, 12, 0, 0, 1, 0, 1, 7, 0, 0, 0, 2, 1, 2]);
        }
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&u16::try_from(body.len()).unwrap_or(0).to_be_bytes());
        handshake.extend_from_slice(&body);
        handshake
    }

    /// [`handshake`] without ECH, split into records of at most `record` bytes.
    pub(crate) fn hello(name: &str, record: usize) -> Vec<u8> {
        let handshake = handshake(name, false);
        let mut stream = Vec::new();
        for chunk in handshake.chunks(record) {
            stream.extend_from_slice(&[22, 3, 1]);
            stream.extend_from_slice(&u16::try_from(chunk.len()).unwrap_or(0).to_be_bytes());
            stream.extend_from_slice(chunk);
        }
        stream
    }

    #[test]
    fn reads_the_name_from_one_record_or_several() {
        let found = ServerName::Found(Hello {
            name: "watch.test".into(),
            ech: false,
        });
        assert_eq!(server_name(&hello("Watch.Test", 1000)), found);
        assert_eq!(server_name(&hello("watch.test", 20)), found);
    }

    #[test]
    fn says_whether_the_hello_offers_ech() {
        assert_eq!(
            from_handshake(&handshake("public.example", true)),
            ServerName::Found(Hello {
                name: "public.example".into(),
                ech: true,
            })
        );
        let mut inner = handshake("public.example", true);
        let at = inner.len() - 12;
        assert_eq!(inner[at], 0, "the ECHClientHello's type");
        inner[at] = 1;
        assert_eq!(
            from_handshake(&inner),
            ServerName::Found(Hello {
                name: "public.example".into(),
                ech: false,
            })
        );
    }

    #[test]
    fn waits_for_more_and_gives_up_on_other_streams() {
        let stream = hello("watch.test", 20);
        for cut in 0..stream.len() {
            assert_eq!(
                server_name(&stream[..cut]),
                ServerName::Incomplete,
                "cut at {cut}"
            );
        }
        assert_eq!(server_name(b"GET / HTTP/1.1\r\n"), ServerName::None);
        assert_eq!(server_name(b"SSH-2.0-OpenSSH_9.9\r\n"), ServerName::None);
        let mut bad = hello("watch test", 1000);
        assert_eq!(server_name(&bad), ServerName::None);
        bad[0] = 23;
        assert_eq!(server_name(&bad), ServerName::None);
    }
}
