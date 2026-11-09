//! The server name an app sends in the first message of a TLS connection, the `ClientHello`'s
//! `server_name` extension (RFC 8446 4.1.2, RFC 6066 3), read from the start of the app's byte stream
//! (W3). Nothing is decrypted: the `ClientHello` is sent in the clear. With Encrypted Client Hello the
//! name read is the outer, public one, which names the provider, not the site.
//!
//! The bytes come from any app, so nothing here may panic or read outside the slice
//! (`fuzz_targets/tls.rs`).

/// The most bytes of a stream looked at before giving up: a `ClientHello` with post-quantum key shares
/// spans more than one TCP segment, but fits in this.
pub const MAX_HELLO: usize = 16 * 1024;

/// What the start of a stream says about its server name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerName {
    /// The name, in lower case.
    Found(String),
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
    match hello_length(&handshake) {
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
            client_hello_name(&handshake[4..needed]).map_or(ServerName::None, ServerName::Found)
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

/// The `host_name` of the `server_name` extension of a `ClientHello` body.
fn client_hello_name(hello: &[u8]) -> Option<String> {
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
    while at + 4 <= extensions_end {
        let kind = u16_at(hello, at)?;
        let length = u16_at(hello, at + 2)?;
        let data = hello.get(at + 4..at + 4 + length)?;
        at += 4 + length;
        if kind != 0 {
            continue;
        }
        // server_name: a list, each entry a type (0: host_name) and a name.
        let list_end = 2 + u16_at(data, 0)?;
        let mut entry = 2;
        while entry + 3 <= list_end.min(data.len()) {
            let name_length = u16_at(data, entry + 1)?;
            let name = data.get(entry + 3..entry + 3 + name_length)?;
            if data[entry] == 0 {
                return valid_name(name);
            }
            entry += 3 + name_length;
        }
        return None;
    }
    None
}

/// A host name of printable ASCII without spaces, in lower case.
fn valid_name(name: &[u8]) -> Option<String> {
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
mod tests {
    use super::*;

    /// A minimal `ClientHello` for `name`, with the extension after another one, split into records of
    /// at most `record` bytes.
    pub(crate) fn hello(name: &str, record: usize) -> Vec<u8> {
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
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&u16::try_from(body.len()).unwrap_or(0).to_be_bytes());
        handshake.extend_from_slice(&body);
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
        assert_eq!(
            server_name(&hello("Watch.Test", 1000)),
            ServerName::Found("watch.test".into())
        );
        assert_eq!(
            server_name(&hello("watch.test", 20)),
            ServerName::Found("watch.test".into())
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
