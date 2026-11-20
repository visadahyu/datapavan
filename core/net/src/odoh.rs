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
    seal_with(
        key,
        query,
        padding,
        &mut hpke::rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// [`seal`] with the ephemeral key's material from `rng`: the system's in the product, fixed in the tests that
/// check the bytes against an independent implementation.
fn seal_with<R: hpke::rand_core::CryptoRng>(
    key: &TargetKey,
    query: &[u8],
    padding: usize,
    rng: &mut R,
) -> Option<Sealed> {
    let plaintext = ObliviousDoHMessagePlaintext::new(query, padding);
    let (message, secret) = odoh_rs::encrypt_query(&plaintext, &key.contents, rng).ok()?;
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
        let mut longer = answer.clone();
        longer.push(0);
        assert_eq!(
            open(&first_again, &longer),
            None,
            "a byte after the message"
        );
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

    /// Random numbers that are not: the bytes given, then zeros.
    struct Fixed(Vec<u8>);

    impl hpke::rand_core::TryRng for Fixed {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dst.iter_mut() {
                *byte = if self.0.is_empty() {
                    0
                } else {
                    self.0.remove(0)
                };
            }
            Ok(())
        }
    }

    impl hpke::rand_core::TryCryptoRng for Fixed {}

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
        let Some(sealed) = seal_with(&key, &oracle("message"), 0, &mut Fixed(oracle("ikm-e")))
        else {
            unreachable!("sealed")
        };
        assert_eq!(
            sealed.body,
            oracle("query"),
            "the same bytes as the oracle's"
        );
        assert_eq!(open(&sealed, &oracle("response")), Some(oracle("answer")));
    }

    /// HPKE against RFC 9180's test vectors, A.1.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base
    /// mode): the receiver's setup opens the vector's ciphertexts in order and exports its values, and the sender's,
    /// with the vector's ephemeral key material, gives its `enc` and seals its first ciphertext.
    #[test]
    fn hpke_meets_rfc_9180s_vectors() {
        use hpke::aead::AesGcm128;
        use hpke::kdf::HkdfSha256;
        use hpke::kem::X25519HkdfSha256;
        use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let Ok(sk_r) = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&unhex(
            "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        )) else {
            unreachable!("skRm")
        };
        let Ok(enc) = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&unhex(
            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        )) else {
            unreachable!("enc")
        };
        let Ok(mut receiver) = hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk_r,
            &enc,
            &info,
        ) else {
            unreachable!("the receiver's setup")
        };
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
        for (aad, ct) in [
            (
                "436f756e742d30",
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            ),
            (
                "436f756e742d31",
                "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
            ),
            (
                "436f756e742d32",
                "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
            ),
        ] {
            assert_eq!(
                receiver.open(&unhex(ct), &unhex(aad)).ok(),
                Some(pt.clone())
            );
        }
        for (context, value) in [
            (
                "",
                "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
            ),
            (
                "00",
                "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
            ),
            (
                "54657374436f6e74657874",
                "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931",
            ),
        ] {
            let mut out = [0u8; 32];
            assert!(receiver.export(&unhex(context), &mut out).is_ok());
            assert_eq!(out.to_vec(), unhex(value));
        }
        let Ok(pk_r) = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&unhex(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        )) else {
            unreachable!("pkRm")
        };
        let mut ikm_e = Fixed(unhex(
            "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
        ));
        let Ok((enc, mut sender)) = hpke::setup_sender_with_rng::<
            AesGcm128,
            HkdfSha256,
            X25519HkdfSha256,
        >(&OpModeS::Base, &pk_r, &info, &mut ikm_e) else {
            unreachable!("the sender's setup")
        };
        assert_eq!(
            enc.to_bytes().to_vec(),
            unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
        );
        assert_eq!(
            sender.seal(&pt, &unhex("436f756e742d30")).ok(),
            Some(unhex(
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
            ))
        );
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
