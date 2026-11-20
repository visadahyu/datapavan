//! Oblivious DoH (RFC 9230), the client's side, for the names of apps that go directly (W8, part 1, ADR 0042):
//! a query sealed to a target's public key, which only the target can open, sent to a relay that sees the
//! phone's address but not the question; the answer, sealed by the target to a secret only this query holds.
//! Each query is sealed afresh, with its own ephemeral key, so two attempts of one lookup (a hedge to the second
//! pair) cannot be linked by their bytes.
//!
//! The framing is this module's (RFC 9230 is short) and the HPKE the engine's own ([`crate::hpke`]), with the
//! suite RFC 9230 makes mandatory and the only one every public target offers (DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256, AES-128-GCM): W8's fix round replaced Cloudflare's `odoh-rs` and the `hpke` crate, a second crypto
//! stack, to keep the native library within its gate. `odoh-rs` stays in the tests, with an implementation in
//! Python, as independent references: a query sealed here opens there, and theirs here.
//!
//! Every function takes bytes a target, a relay or the data pack can choose, so none may panic
//! (`fuzz_targets/odoh.rs`).

use crate::hpke::{self, NK, NN, NPK};

/// The media type of a sealed query and its answer (RFC 9230 4.1).
pub const MEDIA_TYPE: &str = "application/oblivious-dns-message";

/// The `odohconfig` key of an HTTPS record's parameters (RFC 9230 6).
pub const KEY_ODOHCONFIG: u16 = 32769;

/// The one version of a configuration (RFC 9230 6).
const VERSION: u16 = 0x0001;
/// The message types (RFC 9230 4.1).
const QUERY: u8 = 0x01;
const RESPONSE: u8 = 0x02;
/// The length of a response's nonce: `max(Nn, Nk)` (RFC 9230 4.3).
const RESPONSE_NONCE: usize = 16;

/// Reads a big-endian `u16` at `at`.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

/// Two bytes of length, then `bytes`.
fn put_lengthed(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    out.extend_from_slice(&u16::try_from(bytes.len()).ok()?.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

/// The bytes after two bytes of length at `at`, and where they end.
fn lengthed(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let length = usize::from(u16_at(bytes, at)?);
    let end = at.checked_add(2 + length)?;
    Some((bytes.get(at + 2..end)?, end))
}

/// A target's public key, as one of its configurations gives it, with the key's identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetKey {
    public_key: [u8; NPK],
    /// The configuration's identifier (RFC 9230 6.2): `Expand(Extract("", contents), "odoh key id", Nh)`.
    key_id: [u8; 32],
    /// The configurations' bytes it came from, to tell two copies apart or alike.
    configs: Vec<u8>,
}

impl TargetKey {
    /// The first configuration of `configs` (an `ObliviousDoHConfigs`, as `/.well-known/odohconfigs` serves it and an
    /// HTTPS record's `odohconfig` holds it) that this client supports: version 1 with the mandatory suite and an
    /// X25519 key. `None` when there is none, or the bytes are not configurations.
    #[must_use]
    pub fn parse(configs: &[u8]) -> Option<Self> {
        let (list, end) = lengthed(configs, 0)?;
        if end != configs.len() {
            return None;
        }
        let mut at = 0;
        while at < list.len() {
            let version = u16_at(list, at)?;
            let (contents, next) = lengthed(list, at + 2)?;
            at = next;
            if version != VERSION {
                continue;
            }
            // kem_id, kdf_id, aead_id, then the public key with two bytes of length.
            if (
                u16_at(contents, 0)?,
                u16_at(contents, 2)?,
                u16_at(contents, 4)?,
            ) != (0x0020, 0x0001, 0x0001)
            {
                continue;
            }
            let (public_key, used) = lengthed(contents, 6)?;
            let Ok(public_key) = <[u8; NPK]>::try_from(public_key) else {
                continue;
            };
            if used != contents.len() {
                continue;
            }
            let mut key_id = [0u8; 32];
            hpke::expand(
                &hpke::extract(b"", contents),
                &[b"odoh key id"],
                &mut key_id,
            );
            return Some(Self {
                public_key,
                key_id,
                configs: configs.to_vec(),
            });
        }
        None
    }

    /// The configurations' bytes this key was read from.
    #[must_use]
    pub fn configs(&self) -> &[u8] {
        &self.configs
    }
}

/// A query sealed for one target, with what opening its answer needs.
pub struct Sealed {
    /// The bytes to send to the relay: an `ObliviousDoHMessage` of type query.
    pub body: Vec<u8>,
    /// The query's plaintext (`ObliviousDoHMessagePlaintext`), which the answer's key is derived from.
    plaintext: Vec<u8>,
    /// The HPKE context's export for the answer (RFC 9230 4.3).
    secret: [u8; NK],
}

impl std::fmt::Debug for Sealed {
    /// Never the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("body", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Seals the DNS message `query` for the target `key`, with `padding` zero bytes after it (RFC 9230 4.2). The
/// engine pads the DNS message itself with EDNS(0) padding (RFC 8467), which also asks the resolver to pad its
/// answer (RFC 7830), so it passes 0. `None` only when the system gives no random numbers or the message is
/// longer than a query can be.
#[must_use]
pub fn seal(key: &TargetKey, query: &[u8], padding: usize) -> Option<Sealed> {
    let mut ikm = [0u8; 32];
    getrandom::fill(&mut ikm).ok()?;
    seal_with(key, query, padding, &ikm)
}

/// [`seal`] with the ephemeral key derived from `ikm`: random in the product, fixed in the tests that check the
/// bytes against independent implementations.
fn seal_with(key: &TargetKey, query: &[u8], padding: usize, ikm: &[u8]) -> Option<Sealed> {
    let mut plaintext = Vec::with_capacity(query.len() + padding + 4);
    put_lengthed(&mut plaintext, query)?;
    put_lengthed(&mut plaintext, &vec![0u8; padding])?;
    let mut aad = vec![QUERY];
    put_lengthed(&mut aad, &key.key_id)?;
    let (enc, mut context) = hpke::setup_sender(&key.public_key, b"odoh query", ikm)?;
    let sealed = context.seal(&aad, &plaintext)?;
    let mut secret = [0u8; NK];
    context.export(b"odoh response", &mut secret);
    let mut body = aad;
    let mut encrypted = enc.to_vec();
    encrypted.extend_from_slice(&sealed);
    put_lengthed(&mut body, &encrypted)?;
    Some(Sealed {
        body,
        plaintext,
        secret,
    })
}

/// The answer's key and nonce for `sealed`'s query and the target's `nonce` (RFC 9230 4.3).
fn response_keys(
    plaintext: &[u8],
    secret: &[u8; NK],
    nonce: &[u8],
) -> Option<([u8; NK], [u8; NN])> {
    let mut salt = plaintext.to_vec();
    put_lengthed(&mut salt, nonce)?;
    let prk = hpke::extract(&salt, secret);
    let mut key = [0u8; NK];
    hpke::expand(&prk, &[b"odoh key"], &mut key);
    let mut iv = [0u8; NN];
    hpke::expand(&prk, &[b"odoh nonce"], &mut iv);
    Some((key, iv))
}

/// Reads an `ObliviousDoHMessagePlaintext`: the DNS message, when the padding after it is all zeros and nothing
/// follows.
fn read_plaintext(plaintext: &[u8]) -> Option<Vec<u8>> {
    let (message, after) = lengthed(plaintext, 0)?;
    let (padding, end) = lengthed(plaintext, after)?;
    (end == plaintext.len() && padding.iter().all(|&b| b == 0)).then(|| message.to_vec())
}

/// Opens the target's answer `body` to `sealed`: the DNS message inside, or `None` for anything that is not the
/// answer to this very query (a wrong type, a nonce of the wrong length, a tag that does not verify, padding that
/// is not zero, bytes after the message).
#[must_use]
pub fn open(sealed: &Sealed, body: &[u8]) -> Option<Vec<u8>> {
    if *body.first()? != RESPONSE {
        return None;
    }
    let (nonce, after) = lengthed(body, 1)?;
    let (ciphertext, end) = lengthed(body, after)?;
    if nonce.len() != RESPONSE_NONCE || end != body.len() {
        return None;
    }
    let (key, iv) = response_keys(&sealed.plaintext, &sealed.secret, nonce)?;
    let mut aad = vec![RESPONSE];
    put_lengthed(&mut aad, nonce)?;
    read_plaintext(&hpke::open_aead(&key, iv, &aad, ciphertext)?)
}

/// The value of the `odohconfig` parameter of the HTTPS records for `host` in the DNS answer `answer`
/// (RFC 9230 6, RFC 9460): the first record that has one, in the answer's order. `None` when no record of the
/// answer carries one, or the answer is not one.
#[must_use]
pub fn configs_in_https(answer: &[u8], host: &str) -> Option<Vec<u8>> {
    crate::dns::svc_param(answer, host, KEY_ODOHCONFIG)
}

/// A target, for the tests and the fuzzer: its private key and its configurations.
#[cfg(test)]
pub(crate) mod target {
    use super::*;

    /// A target's key pair from fixed key material, and its configurations as the target would serve them.
    #[must_use]
    pub(crate) fn new(ikm: &[u8; 32]) -> ([u8; NPK], Vec<u8>) {
        let (sk, pk) = hpke::derive_key_pair(ikm).unwrap_or(([0; NPK], [0; NPK]));
        let mut contents = Vec::new();
        for id in [0x0020u16, 0x0001, 0x0001] {
            contents.extend_from_slice(&id.to_be_bytes());
        }
        let _ = put_lengthed(&mut contents, &pk);
        let mut config = VERSION.to_be_bytes().to_vec();
        let _ = put_lengthed(&mut config, &contents);
        let mut configs = Vec::new();
        let _ = put_lengthed(&mut configs, &config);
        (sk, configs)
    }

    /// What a target does with a sealed query: opens it with `sk` (whose configurations are `configs`) and seals
    /// `answer` back with `nonce`; the query's DNS message and the answer's body. `None` for a query to another
    /// key, or one that does not open.
    #[must_use]
    pub(crate) fn answer(
        sk: &[u8; NPK],
        configs: &[u8],
        sealed: &[u8],
        answer: &[u8],
        nonce: [u8; RESPONSE_NONCE],
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let key = TargetKey::parse(configs)?;
        if *sealed.first()? != QUERY {
            return None;
        }
        let (key_id, after) = lengthed(sealed, 1)?;
        let (encrypted, end) = lengthed(sealed, after)?;
        if key_id != key.key_id || end != sealed.len() {
            return None;
        }
        let mut aad = vec![QUERY];
        put_lengthed(&mut aad, key_id)?;
        let mut context = hpke::setup_receiver(encrypted.get(..NPK)?, sk, b"odoh query")?;
        let plaintext = context.open(&aad, encrypted.get(NPK..)?)?;
        let query = read_plaintext(&plaintext)?;
        let mut secret = [0u8; NK];
        context.export(b"odoh response", &mut secret);
        let (response_key, iv) = response_keys(&plaintext, &secret, &nonce)?;
        let mut reply = Vec::new();
        put_lengthed(&mut reply, answer)?;
        put_lengthed(&mut reply, &[])?;
        let mut response_aad = vec![RESPONSE];
        put_lengthed(&mut response_aad, &nonce)?;
        let sealed_reply = hpke::seal_aead(&response_key, iv, &response_aad, &reply)?;
        let mut body = response_aad;
        put_lengthed(&mut body, &sealed_reply)?;
        Some((query, body))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn target(ikm: &[u8; 32]) -> ([u8; NPK], Vec<u8>) {
        super::target::new(ikm)
    }

    pub(crate) fn answer_as_target(
        sk: &[u8; NPK],
        configs: &[u8],
        sealed: &[u8],
        answer: &[u8],
        nonce: [u8; 16],
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        super::target::answer(sk, configs, sealed, answer, nonce)
    }

    #[test]
    fn a_query_sealed_here_opens_at_the_target_and_its_answer_opens_here() {
        let (sk, configs) = target(&[7; 32]);
        let Some(key) = TargetKey::parse(&configs) else {
            unreachable!("a key")
        };
        let Some(sealed) = seal(&key, b"a dns query", 0) else {
            unreachable!("sealed")
        };
        let Some((query, answer)) =
            answer_as_target(&sk, &configs, &sealed.body, b"a dns answer", [9; 16])
        else {
            unreachable!("the target opens it")
        };
        assert_eq!(query, b"a dns query");
        assert_eq!(
            open(&sealed, &answer).as_deref(),
            Some(&b"a dns answer"[..])
        );
    }

    #[test]
    fn each_seal_of_one_query_differs() {
        let (_, configs) = target(&[7; 32]);
        let Some(key) = TargetKey::parse(&configs) else {
            unreachable!("a key")
        };
        let one = seal(&key, b"q", 0).map(|s| s.body);
        let two = seal(&key, b"q", 0).map(|s| s.body);
        assert!(one.is_some() && two.is_some());
        assert_ne!(one, two, "a fresh ephemeral key each time");
    }

    #[test]
    fn an_answer_to_another_query_or_tampered_does_not_open() {
        let (sk, configs) = target(&[7; 32]);
        let Some(key) = TargetKey::parse(&configs) else {
            unreachable!("a key")
        };
        let (Some(first), Some(second)) = (seal(&key, b"one", 0), seal(&key, b"two", 0)) else {
            unreachable!("sealed")
        };
        let Some((_, answer)) = answer_as_target(&sk, &configs, &first.body, b"for one", [1; 16])
        else {
            unreachable!("answered")
        };
        assert_eq!(open(&second, &answer), None, "not this query's answer");
        let mut longer = answer.clone();
        longer.push(0);
        assert_eq!(open(&first, &longer), None, "a byte after the message");
        let mut tampered = answer;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(open(&first, &tampered), None, "the tag fails");
    }

    #[test]
    fn another_targets_key_cannot_open_the_query() {
        let (_, configs) = target(&[7; 32]);
        let (other_sk, other_configs) = target(&[8; 32]);
        let Some(key) = TargetKey::parse(&configs) else {
            unreachable!("a key")
        };
        let Some(sealed) = seal(&key, b"q", 0) else {
            unreachable!("sealed")
        };
        assert!(answer_as_target(&other_sk, &other_configs, &sealed.body, b"a", [0; 16]).is_none());
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0))
            .collect()
    }

    /// The oracle's values (testdata/odoh/oracle.txt, written by oracle.py, an implementation of RFC 9180 and 9230
    /// of its own in Python, after the research's probe).
    fn oracle(key: &str) -> Vec<u8> {
        let text = include_str!("../testdata/odoh/oracle.txt");
        let line = text
            .lines()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(' ')))
            .unwrap_or("");
        unhex(line)
    }

    /// RFC 9230 has no test vectors: the engine's sealed query must be the oracle's to the byte, from the same
    /// key material, and the oracle's answer, sealed as a target seals it, must open to its message.
    #[test]
    fn the_sealed_query_and_the_opened_answer_match_an_independent_implementation() {
        let Some(key) = TargetKey::parse(&oracle("configs")) else {
            unreachable!("the oracle's configs read")
        };
        let Some(sealed) = seal_with(&key, &oracle("message"), 0, &oracle("ikm-e")) else {
            unreachable!("sealed")
        };
        assert_eq!(
            sealed.body,
            oracle("query"),
            "the same bytes as the oracle's"
        );
        assert_eq!(open(&sealed, &oracle("response")), Some(oracle("answer")));
    }

    /// Cloudflare's `odoh-rs` on rozbb's `hpke`, which the engine used before, as a second reference: a query sealed
    /// here opens at its target, and its target's answer opens here.
    #[test]
    fn a_query_sealed_here_opens_at_odoh_rs_and_its_answer_opens_here() {
        use bytes::Bytes;
        use odoh_rs::{
            ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHKeyPair, ObliviousDoHMessage,
            ObliviousDoHMessagePlaintext,
        };
        let pair = ObliviousDoHKeyPair::from_parameters(0x0020, 0x0001, 0x0001, &[5; 32]);
        let configs: ObliviousDoHConfigs =
            vec![ObliviousDoHConfig::from(pair.public().clone())].into();
        let Ok(bytes) = odoh_rs::compose(&configs) else {
            unreachable!("composed")
        };
        let Some(key) = TargetKey::parse(&bytes) else {
            unreachable!("odoh-rs's configs read here")
        };
        let Some(sealed) = seal(&key, b"a query", 3) else {
            unreachable!("sealed")
        };
        let mut buffer = Bytes::copy_from_slice(&sealed.body);
        let Ok(message) = odoh_rs::parse::<ObliviousDoHMessage, _>(&mut buffer) else {
            unreachable!("odoh-rs reads the message")
        };
        let Ok((query, secret)) = odoh_rs::decrypt_query(&message, &pair) else {
            unreachable!("odoh-rs opens it")
        };
        assert_eq!(query.clone().into_msg().as_ref(), b"a query");
        let reply = ObliviousDoHMessagePlaintext::new(b"an answer", 0);
        let Ok(response) = odoh_rs::encrypt_response(&query, &reply, secret, [4; 16]) else {
            unreachable!("odoh-rs seals the answer")
        };
        let Ok(body) = odoh_rs::compose(&response) else {
            unreachable!("composed")
        };
        assert_eq!(open(&sealed, &body).as_deref(), Some(&b"an answer"[..]));
    }

    #[test]
    fn configurations_that_are_not_are_refused() {
        assert!(TargetKey::parse(&[]).is_none());
        assert!(TargetKey::parse(&[0, 4, 0, 1, 0, 0]).is_none());
        let (_, configs) = target(&[7; 32]);
        let mut unknown = configs.clone();
        // An unknown version only: nothing supported.
        unknown[2] = 0xff;
        assert!(TargetKey::parse(&unknown).is_none());
        let mut longer = configs;
        longer.push(0);
        assert!(TargetKey::parse(&longer).is_none(), "a byte after the list");
    }
}
