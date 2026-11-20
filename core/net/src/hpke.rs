//! HPKE (RFC 9180), base mode, for Oblivious DoH's one suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
//! (W8, part 1, fix round), in place of the `hpke` crate. Written over primitives the native library already holds:
//! `x25519-dalek` 2 (`GotaTun`'s handshake), `RustCrypto`'s `hkdf` and `aes-gcm` (the QUIC Initials' reader), so
//! that ODoH adds no crypto stack of its own. `aws-lc-rs`'s X25519, HMAC and AES-GCM were tried first, as one audited
//! provider: they brought 0.76 MB on arm64 and 0.99 MB on `x86_64` of `aws-lc`'s C into the library, which uses only
//! its ChaCha20-Poly1305, for `WireGuard` (measured, ADR 0042). No `unsafe`. Held to RFC 9180's test vectors (A.1.1) on
//! both sides and, through ODoH, to an implementation of its own in Python (`testdata/odoh/oracle.py`) and to
//! Cloudflare's `odoh-rs`; fuzzed through `fuzz_targets/odoh.rs`.
//!
//! Only what ODoH needs is here: the sender's setup from a key's material (random in the product, fixed in the
//! tests), sealing, the exporter, and, for the tests, the receiver's setup and opening.

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret, x25519};

/// The KEM's, KDF's and AEAD's identifiers (RFC 9180 7.1, 7.2, 7.3).
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;
/// Lengths: the shared secret and the hash (32), AES-128's key (16), its nonce (12), an X25519 key (32).
const NH: usize = 32;
/// The AEAD key's length.
pub const NK: usize = 16;
/// The AEAD nonce's length.
pub const NN: usize = 12;
/// An X25519 public key's length, which is also `enc`'s.
pub const NPK: usize = 32;

/// The KEM's suite identifier, `"KEM" || I2OSP(kem_id, 2)`.
fn kem_suite() -> [u8; 5] {
    let id = KEM_ID.to_be_bytes();
    [b'K', b'E', b'M', id[0], id[1]]
}

/// The whole suite's identifier, `"HPKE" || kem_id || kdf_id || aead_id`.
fn hpke_suite() -> [u8; 10] {
    let (k, d, a) = (
        KEM_ID.to_be_bytes(),
        KDF_ID.to_be_bytes(),
        AEAD_ID.to_be_bytes(),
    );
    [b'H', b'P', b'K', b'E', k[0], k[1], d[0], d[1], a[0], a[1]]
}

/// HKDF-Extract (RFC 5869) with SHA-256: `NH` zeros as the salt when it is empty.
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; NH] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; NH];
    out.copy_from_slice(&prk);
    out
}

/// HKDF-Expand (RFC 5869) of `prk` with `info` given in parts, into `out`, at most 255 hashes long; `out` is left
/// as it was for a longer one, which no caller asks.
pub fn expand(prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
    if let Ok(hkdf) = Hkdf::<Sha256>::from_prk(prk) {
        let _ = hkdf.expand_multi_info(info, out);
    }
}

/// `LabeledExtract(salt, label, ikm)` under `suite` (RFC 9180 4).
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; NH] {
    let mut labeled = Vec::with_capacity(7 + suite.len() + label.len() + ikm.len());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    extract(salt, &labeled)
}

/// `LabeledExpand(prk, label, info, L)` under `suite` into `out`, whose length is L.
fn labeled_expand(suite: &[u8], prk: &[u8], label: &[u8], info: &[u8], out: &mut [u8]) {
    let length = u16::try_from(out.len()).unwrap_or(u16::MAX).to_be_bytes();
    expand(prk, &[&length, b"HPKE-v1", suite, label, info], out);
}

/// `DeriveKeyPair(ikm)` for X25519 (RFC 9180 7.1.3): the private key's bytes and the public key's.
#[must_use]
pub fn derive_key_pair(ikm: &[u8]) -> Option<([u8; NPK], [u8; NPK])> {
    let suite = kem_suite();
    let dkp = labeled_extract(&suite, b"", b"dkp_prk", ikm);
    let mut sk = [0u8; NPK];
    labeled_expand(&suite, &dkp, b"sk", b"", &mut sk);
    let public = public_of(&sk);
    Some((sk, public))
}

/// The X25519 public key of the private key `sk`.
fn public_of(sk: &[u8; NPK]) -> [u8; NPK] {
    PublicKey::from(&StaticSecret::from(*sk)).to_bytes()
}

/// X25519 of the private key `sk` and the public key `pk`, refused when it is all zeros (a public key of small order,
/// RFC 9180 7.1.4), checked without a branch on any byte.
fn dh(sk: &[u8; NPK], pk: &[u8]) -> Option<[u8; NPK]> {
    let pk: [u8; NPK] = pk.try_into().ok()?;
    let shared = x25519(*sk, pk);
    (shared.iter().fold(0u8, |any, byte| any | byte) != 0).then_some(shared)
}

/// `ExtractAndExpand(dh, kem_context)` of DHKEM (RFC 9180 4.1).
fn shared_secret(dh: &[u8; NPK], enc: &[u8; NPK], pk_r: &[u8; NPK]) -> [u8; NH] {
    let suite = kem_suite();
    let eae = labeled_extract(&suite, b"", b"eae_prk", dh);
    let mut context = [0u8; 2 * NPK];
    context[..NPK].copy_from_slice(enc);
    context[NPK..].copy_from_slice(pk_r);
    let mut out = [0u8; NH];
    labeled_expand(&suite, &eae, b"shared_secret", &context, &mut out);
    out
}

/// An HPKE context, base mode: the AEAD's key, its base nonce, the exporter's secret and the sequence number.
pub struct Context {
    key: [u8; NK],
    base_nonce: [u8; NN],
    exporter: [u8; NH],
    sequence: u64,
}

impl Context {
    /// The key schedule (RFC 9180 5.1) of a base-mode context from the KEM's `shared` secret and `info`.
    fn schedule(shared: &[u8; NH], info: &[u8]) -> Self {
        let suite = hpke_suite();
        let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
        let mut context = [0u8; 1 + 2 * NH];
        context[1..=NH].copy_from_slice(&psk_id_hash);
        context[1 + NH..].copy_from_slice(&info_hash);
        let secret = labeled_extract(&suite, shared, b"secret", b"");
        let mut out = Self {
            key: [0; NK],
            base_nonce: [0; NN],
            exporter: [0; NH],
            sequence: 0,
        };
        labeled_expand(&suite, &secret, b"key", &context, &mut out.key);
        labeled_expand(
            &suite,
            &secret,
            b"base_nonce",
            &context,
            &mut out.base_nonce,
        );
        labeled_expand(&suite, &secret, b"exp", &context, &mut out.exporter);
        out
    }

    /// The nonce of the current sequence number, then the number advanced.
    fn next_nonce(&mut self) -> Option<[u8; NN]> {
        let mut nonce = self.base_nonce;
        for (byte, seq) in nonce[NN - 8..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *byte ^= seq;
        }
        self.sequence = self.sequence.checked_add(1)?;
        Some(nonce)
    }

    /// `Seal(aad, pt)`: the ciphertext with its tag.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.next_nonce()?;
        seal_aead(&self.key, nonce, aad, plaintext)
    }

    /// `Open(aad, ct)`: the plaintext, or `None` when the tag does not verify.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.next_nonce()?;
        open_aead(&self.key, nonce, aad, ciphertext)
    }

    /// `Export(exporter_context, L)` into `out` (RFC 9180 5.3).
    pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) {
        labeled_expand(&hpke_suite(), &self.exporter, b"sec", exporter_context, out);
    }
}

/// The length of AES-GCM's tag.
const TAG: usize = 16;

/// AES-128-GCM's open of `ciphertext` (with its tag at the end) under `key` and `nonce`: the plaintext, or `None`.
#[must_use]
pub fn open_aead(
    key: &[u8; NK],
    nonce: [u8; NN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    let split = ciphertext.len().checked_sub(TAG)?;
    let (body, tag) = ciphertext.split_at(split);
    let mut plaintext = body.to_vec();
    let tag = Tag::<Aes128Gcm>::try_from(tag).ok()?;
    cipher
        .decrypt_inout_detached(
            &Nonce::<Aes128Gcm>::from(nonce),
            aad,
            plaintext.as_mut_slice().into(),
            &tag,
        )
        .ok()?;
    Some(plaintext)
}

/// AES-128-GCM's seal of `plaintext` under `key` and `nonce`, its tag at the end.
#[must_use]
pub fn seal_aead(key: &[u8; NK], nonce: [u8; NN], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    let mut sealed = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(
            &Nonce::<Aes128Gcm>::from(nonce),
            aad,
            sealed.as_mut_slice().into(),
        )
        .ok()?;
    sealed.extend_from_slice(&tag);
    Some(sealed)
}

/// `SetupBaseS(pkR, info)` with the ephemeral key derived from `ikm_e` (`DeriveKeyPair`, RFC 9180 7.1.3): `enc` and
/// the sender's context. The product passes 32 random bytes; the tests the vectors' material.
#[must_use]
pub fn setup_sender(pk_r: &[u8], info: &[u8], ikm_e: &[u8]) -> Option<([u8; NPK], Context)> {
    let pk_r: [u8; NPK] = pk_r.try_into().ok()?;
    let (sk_e, enc) = derive_key_pair(ikm_e)?;
    let dh = dh(&sk_e, &pk_r)?;
    Some((
        enc,
        Context::schedule(&shared_secret(&dh, &enc, &pk_r), info),
    ))
}

/// `SetupBaseR(enc, skR, info)`: the receiver's context, for the tests and the fuzzer's target side.
#[must_use]
pub fn setup_receiver(enc: &[u8], sk_r: &[u8; NPK], info: &[u8]) -> Option<Context> {
    let enc: [u8; NPK] = enc.try_into().ok()?;
    let pk_r = public_of(sk_r);
    let dh = dh(sk_r, &enc)?;
    Some(Context::schedule(&shared_secret(&dh, &enc, &pk_r), info))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0))
            .collect()
    }

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    /// RFC 9180, A.1.1.1: sequence number, AAD and ciphertext.
    const SEALED: [(u64, &str, &str); 3] = [
        (
            0,
            "436f756e742d30",
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
        ),
        (
            1,
            "436f756e742d31",
            "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
        ),
        (
            2,
            "436f756e742d32",
            "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
        ),
    ];
    /// RFC 9180, A.1.1.2: exporter context and exported value.
    const EXPORTED: [(&str, &str); 3] = [
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
    ];

    #[test]
    fn derive_key_pair_meets_the_vectors_keys() {
        let ikm_r = unhex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
        let Some((sk, pk)) = derive_key_pair(&ikm_r) else {
            unreachable!("derived")
        };
        assert_eq!(
            sk.to_vec(),
            unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
        );
        assert_eq!(
            pk.to_vec(),
            unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
        );
    }

    #[test]
    fn the_sender_meets_rfc_9180s_vectors() {
        let ikm_e = unhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let pk_r = unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let Some((enc, mut sender)) = setup_sender(&pk_r, &unhex(INFO), &ikm_e) else {
            unreachable!("the sender's setup")
        };
        assert_eq!(
            enc.to_vec(),
            unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
        );
        assert_eq!(
            sender.key.to_vec(),
            unhex("4531685d41d65f03dc48f6b8302c05b0")
        );
        assert_eq!(
            sender.base_nonce.to_vec(),
            unhex("56d890e5accaaf011cff4b7d")
        );
        for (_, aad, ct) in SEALED {
            assert_eq!(sender.seal(&unhex(aad), &unhex(PT)), Some(unhex(ct)));
        }
        for (context, value) in EXPORTED {
            let mut out = [0u8; 32];
            sender.export(&unhex(context), &mut out);
            assert_eq!(out.to_vec(), unhex(value));
        }
    }

    #[test]
    fn the_receiver_meets_rfc_9180s_vectors_and_refuses_a_changed_ciphertext() {
        let sk_r: [u8; NPK] =
            unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
                .try_into()
                .unwrap_or([0; NPK]);
        let enc = unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        let Some(mut receiver) = setup_receiver(&enc, &sk_r, &unhex(INFO)) else {
            unreachable!("the receiver's setup")
        };
        for (sequence, aad, ct) in SEALED {
            assert_eq!(receiver.sequence, sequence);
            assert_eq!(receiver.open(&unhex(aad), &unhex(ct)), Some(unhex(PT)));
        }
        for (context, value) in EXPORTED {
            let mut out = [0u8; 32];
            receiver.export(&unhex(context), &mut out);
            assert_eq!(out.to_vec(), unhex(value));
        }
        let Some(mut again) = setup_receiver(&enc, &sk_r, &unhex(INFO)) else {
            unreachable!("the receiver's setup")
        };
        let mut changed = unhex(SEALED[0].2);
        changed[0] ^= 1;
        assert_eq!(again.open(&unhex(SEALED[0].1), &changed), None);
    }

    #[test]
    fn a_public_key_of_small_order_is_refused() {
        // The all-zero point: X25519 with it is all zeros.
        assert!(setup_sender(&[0u8; 32], b"", &[1u8; 32]).is_none());
        assert!(
            setup_sender(&[1u8; 31], b"", &[1u8; 32]).is_none(),
            "a key of the wrong length"
        );
    }
}
