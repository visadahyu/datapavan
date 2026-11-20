//! Oblivious DoH (RFC 9230), the client's side, for the names of apps that go directly (W8, part 1, ADR 0042):
//! a query sealed to a target's public key, which only the target can open, sent to a relay that sees the
//! phone's address but not the question; the answer, sealed by the target to a secret only this query holds.
//! Each query is sealed afresh, with its own ephemeral key, so two attempts of one lookup (a hedge to the second
//! pair) cannot be linked by their bytes.
//!
//! The cryptography is Cloudflare's `odoh-rs` on rozbb's `hpke`, with the suite RFC 9230 makes mandatory and the
//! only one every public target offers (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM). This module reads
//! the target's configurations and keeps the secret between a query and its answer; it holds no TLS: the sealed
//! bytes go to the relay over Android's own TLS, from Watch's Kotlin side.
//!
//! Every function takes bytes a target, a relay or the data pack can choose, so none may panic
//! (`fuzz_targets/odoh.rs`).

use bytes::Bytes;
use odoh_rs::{
    ObliviousDoHConfigContents, ObliviousDoHConfigs, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, OdohSecret,
};

/// The media type of a sealed query and its answer (RFC 9230 4.1).
pub const MEDIA_TYPE: &str = "application/oblivious-dns-message";

/// The `odohconfig` key of an HTTPS record's parameters (RFC 9230 6).
pub const KEY_ODOHCONFIG: u16 = 32769;

/// A target's public key, as one of its configurations gives it, with the key's identifier.
#[derive(Clone, Debug)]
pub struct TargetKey {
    contents: ObliviousDoHConfigContents,
    /// The configurations' bytes it came from, to tell two copies apart or alike.
    configs: Vec<u8>,
}

impl PartialEq for TargetKey {
    fn eq(&self, other: &Self) -> bool {
        self.configs == other.configs
    }
}

impl Eq for TargetKey {}

impl TargetKey {
    /// The first configuration of `configs` (an `ObliviousDoHConfigs`, as `/.well-known/odohconfigs` serves it
    /// and an HTTPS record's `odohconfig` holds it) that this client supports: version 1 with the mandatory
    /// suite. `None` when there is none, or the bytes are not configurations.
    #[must_use]
    pub fn parse(configs: &[u8]) -> Option<Self> {
        let mut buffer = Bytes::copy_from_slice(configs);
        let read: ObliviousDoHConfigs = odoh_rs::parse(&mut buffer).ok()?;
        let contents: ObliviousDoHConfigContents = read.supported().into_iter().next()?.into();
        // A key that cannot be read as an X25519 public key is refused here, not at the first query.
        contents.identifier().ok()?;
        Some(Self {
            contents,
            configs: configs.to_vec(),
        })
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
    plaintext: ObliviousDoHMessagePlaintext,
    secret: OdohSecret,
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
    if query.len() > usize::from(u16::MAX) || padding > usize::from(u16::MAX) {
        return None;
    }
    let plaintext = ObliviousDoHMessagePlaintext::new(query, padding);
    let mut rng = hpke::rand_core::UnwrapErr(getrandom::SysRng);
    let (message, secret) = odoh_rs::encrypt_query(&plaintext, &key.contents, &mut rng).ok()?;
    let body = odoh_rs::compose(&message).ok()?.to_vec();
    Some(Sealed {
        body,
        plaintext,
        secret,
    })
}

/// Opens the target's answer `body` to `sealed`: the DNS message inside, or `None` for anything that is not
/// the answer to this very query (a wrong type, a nonce of the wrong length, a tag that does not verify,
/// padding that is not zero).
#[must_use]
pub fn open(sealed: &Sealed, body: &[u8]) -> Option<Vec<u8>> {
    let mut buffer = Bytes::copy_from_slice(body);
    let message: ObliviousDoHMessage = odoh_rs::parse(&mut buffer).ok()?;
    if !buffer.is_empty() {
        return None;
    }
    let opened = odoh_rs::decrypt_response(&sealed.plaintext, &message, sealed.secret).ok()?;
    Some(opened.into_msg().to_vec())
}

/// The value of the `odohconfig` parameter of the HTTPS records for `host` in the DNS answer `answer`
/// (RFC 9230 6, RFC 9460): the first record that has one, in the answer's order. `None` when no record of the
/// answer carries one, or the answer is not one.
#[must_use]
pub fn configs_in_https(answer: &[u8], host: &str) -> Option<Vec<u8>> {
    crate::dns::svc_param(answer, host, KEY_ODOHCONFIG)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use odoh_rs::{ObliviousDoHConfig, ObliviousDoHKeyPair, ResponseNonce};

    /// A target's key pair from fixed key material, and its configurations as the target would serve them.
    pub(crate) fn target(ikm: &[u8; 32]) -> (ObliviousDoHKeyPair, Vec<u8>) {
        let pair = ObliviousDoHKeyPair::from_parameters(0x0020, 0x0001, 0x0001, ikm);
        let configs: ObliviousDoHConfigs =
            vec![ObliviousDoHConfig::from(pair.public().clone())].into();
        let Ok(bytes) = odoh_rs::compose(&configs) else {
            unreachable!("configs compose")
        };
        (pair, bytes.to_vec())
    }

    /// What a target does with a sealed query: opens it and seals `answer` back with `nonce`.
    pub(crate) fn answer_as_target(
        pair: &ObliviousDoHKeyPair,
        sealed: &[u8],
        answer: &[u8],
        nonce: ResponseNonce,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let mut buffer = Bytes::copy_from_slice(sealed);
        let message: ObliviousDoHMessage = odoh_rs::parse(&mut buffer).ok()?;
        let (query, secret) = odoh_rs::decrypt_query(&message, pair).ok()?;
        let reply = ObliviousDoHMessagePlaintext::new(answer, 0);
        let sealed = odoh_rs::encrypt_response(&query, &reply, secret, nonce).ok()?;
        Some((
            query.into_msg().to_vec(),
            odoh_rs::compose(&sealed).ok()?.to_vec(),
        ))
    }

    #[test]
    fn a_query_sealed_here_opens_at_the_target_and_its_answer_opens_here() {
        let (pair, configs) = target(&[7; 32]);
        let Some(key) = TargetKey::parse(&configs) else {
            unreachable!("a key")
        };
        let Some(sealed) = seal(&key, b"a dns query", 0) else {
            unreachable!("sealed")
        };
        let body = sealed.body.clone();
        let Some((query, answer)) = answer_as_target(&pair, &body, b"a dns answer", [9; 16]) else {
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
        let (pair, configs) = target(&[7; 32]);
        let Some(key) = TargetKey::parse(&configs) else {
            unreachable!("a key")
        };
        let (Some(first), Some(second)) = (seal(&key, b"one", 0), seal(&key, b"two", 0)) else {
            unreachable!("sealed")
        };
        let Some((_, answer)) = answer_as_target(&pair, &first.body, b"for one", [1; 16]) else {
            unreachable!("answered")
        };
        assert_eq!(open(&second, &answer), None, "not this query's answer");
        let Some(first_again) = seal(&key, b"one", 0) else {
            unreachable!("sealed")
        };
        let Some((_, mut answer)) = answer_as_target(&pair, &first_again.body, b"x", [1; 16])
        else {
            unreachable!("answered")
        };
        let last = answer.len() - 1;
        answer[last] ^= 1;
        assert_eq!(open(&first_again, &answer), None, "the tag fails");
    }

    #[test]
    fn another_targets_key_cannot_open_the_query() {
        let (_, configs) = target(&[7; 32]);
        let (other, _) = target(&[8; 32]);
        let Some(key) = TargetKey::parse(&configs) else {
            unreachable!("a key")
        };
        let Some(sealed) = seal(&key, b"q", 0) else {
            unreachable!("sealed")
        };
        assert!(answer_as_target(&other, &sealed.body, b"a", [0; 16]).is_none());
    }

    #[test]
    fn configurations_that_are_not_are_refused() {
        assert!(TargetKey::parse(&[]).is_none());
        assert!(TargetKey::parse(&[0, 4, 0, 1, 0, 0]).is_none());
        let (_, mut configs) = target(&[7; 32]);
        // An unknown version only: nothing supported.
        configs[2] = 0xff;
        assert!(TargetKey::parse(&configs).is_none());
    }
}
