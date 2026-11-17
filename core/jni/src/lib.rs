//! Thin JNI bridge between the Android app and [`datapavan_engine`].
//!
//! Every export here is a boundary where data crosses between the JVM and Rust. Keep each one
//! small: convert the arguments, call the engine, convert the result. All logic belongs in the
//! engine crate, which contains no unsafe code.
//!
//! Errors are turned into a Java `RuntimeException` by the chosen error policy. In debug builds,
//! `EnvUnowned::with_env` catches panics so they never unwind into the JVM; release builds use
//! `panic = "abort"`, which ends the process first.

use datapavan_engine::attestation::{self, SecurityLevel, VerifiedBootState};
use datapavan_engine::datapack::{self, Payload, PublicKey};
use datapavan_engine::trackers::Signatures;
use jni::EnvUnowned;
use jni::errors::{Error, ThrowRuntimeExAndDefault};
use jni::objects::{JByteArray, JClass, JIntArray, JString};
use jni::sys::{jint, jlong};
use std::sync::{Arc, RwLock};

/// The tracker signatures that `loadTrackers` read, shared by every `scanDex` call.
static TRACKERS: RwLock<Option<Arc<Signatures>>> = RwLock::new(None);

/// `org.visadahyu.datapavan.core.NativeCore.version()`: the engine version string.
// SAFETY: `no_mangle` exports this function under the JNI-mangled name the JVM resolves for
// `NativeCore.version`. The name is unique within this library, so it cannot clash with another
// symbol, and the signature matches the static Kotlin declaration `external fun version(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_core_NativeCore_version<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> { JString::from_str(env, datapavan_engine::version()) })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `org.visadahyu.datapavan.core.NativeCore.parseAttestation(byte[])`: decodes the `KeyDescription`
/// extension of an attestation certificate, exactly as `X509Certificate.getExtensionValue` returns
/// it; malformed input throws a `RuntimeException`. The result is the record [`encode`] writes.
/// `securityLevel` is the weaker of the attestation's and the key's levels. The values after it come
/// from the hardware-enforced list when it is 1 or 2, and from the software-enforced list only when
/// it is 0, so a value the hardware left out is absent even where the system wrote one into the
/// other list (see the engine's `attestation` module).
// SAFETY: `no_mangle` exports this function under the JNI-mangled name the JVM resolves for
// `NativeCore.parseAttestation`. The name is unique within this library, and the signature matches
// the static Kotlin declaration `external fun parseAttestation(extension: ByteArray): ByteArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_core_NativeCore_parseAttestation<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    extension: JByteArray<'caller>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let bytes = env.convert_byte_array(&extension)?;
            let description = attestation::parse_key_description(&bytes)
                .map_err(|e| Error::ParseFailed(e.to_string()))?;
            env.byte_array_from_slice(&encode(&description))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Format of the record [`encode`] writes, which `AttestationFields.decode` in the app checks.
const ATTESTATION_RECORD: u8 = 1;

/// Writes a `KeyDescription` as the record `AttestationFields.decode` reads, big-endian: the format
/// byte; eight 64-bit integers, -1 where absent: attestationVersion, securityLevel (0 software,
/// 1 trusted environment, 2 `StrongBox`), deviceLocked (0 or 1), verifiedBoot (0 verified,
/// 1 self-signed, 2 unverified, 3 failed), osVersion, then the OS, vendor and boot patch levels as
/// `YYYYMM`; then three byte strings, each a 32-bit length, -1 where absent, and its bytes:
/// attestationChallenge, verifiedBootKey and verifiedBootHash.
fn encode(description: &attestation::KeyDescription<'_>) -> Vec<u8> {
    let level = match description.security_level {
        SecurityLevel::Software => 0,
        SecurityLevel::TrustedEnvironment => 1,
        SecurityLevel::StrongBox => 2,
    };
    let root = description.root_of_trust;
    let boot = root.map_or(-1, |root| match root.verified_boot {
        VerifiedBootState::Verified => 0,
        VerifiedBootState::SelfSigned => 1,
        VerifiedBootState::Unverified => 2,
        VerifiedBootState::Failed => 3,
    });
    let number = |value: Option<u32>| value.map_or(-1, i64::from);
    let mut out = vec![ATTESTATION_RECORD];
    for value in [
        i64::from(description.attestation_version),
        level,
        root.map_or(-1, |root| i64::from(root.device_locked)),
        boot,
        number(description.os_version),
        number(description.os_patch_level),
        number(description.vendor_patch_level),
        number(description.boot_patch_level),
    ] {
        out.extend(value.to_be_bytes());
    }
    for bytes in [
        Some(description.attestation_challenge),
        root.map(|root| root.verified_boot_key),
        root.and_then(|root| root.verified_boot_hash),
    ] {
        // An extension is far shorter than 2 GiB, so every length fits.
        let length = bytes.map_or(-1, |b| i32::try_from(b.len()).unwrap_or(i32::MAX));
        out.extend(length.to_be_bytes());
        out.extend(bytes.unwrap_or_default());
    }
    out
}

/// `org.visadahyu.datapavan.core.NativeCore.loadTrackers(String)`: reads the tracker signatures
/// (`data/exodus/trackers.tsv`) and keeps them for `scanDex`, replacing any loaded before. Returns
/// the number of trackers; malformed data throws a `RuntimeException`.
// SAFETY: `no_mangle` exports this function under the JNI-mangled name the JVM resolves for
// `NativeCore.loadTrackers`. The name is unique within this library, and the signature matches the
// static Kotlin declaration `external fun loadTrackers(tsv: String): Int`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_core_NativeCore_loadTrackers<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    tsv: JString<'caller>,
) -> jint {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let signatures = Signatures::parse(&tsv.try_to_string(env)?)
                .map_err(|e| Error::ParseFailed(e.to_string()))?;
            let count = jint::try_from(signatures.trackers().len()).unwrap_or(jint::MAX);
            let mut slot = TRACKERS
                .write()
                .map_err(|_| Error::ParseFailed("tracker signatures are unavailable".to_owned()))?;
            *slot = Some(Arc::new(signatures));
            Ok(count)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `org.visadahyu.datapavan.core.NativeCore.scanDex(byte[])`: finds the loaded trackers in one DEX
/// file. The result is described on [`scan_result`].
// SAFETY: `no_mangle` exports this function under the JNI-mangled name the JVM resolves for
// `NativeCore.scanDex`. The name is unique within this library, and the signature matches the
// static Kotlin declaration `external fun scanDex(dex: ByteArray): IntArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_core_NativeCore_scanDex<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    dex: JByteArray<'caller>,
) -> JIntArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let bytes = env.convert_byte_array(&dex)?;
            scan_result(env, &bytes)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `org.visadahyu.datapavan.core.NativeCore.scanMappedDex(long, int)`: finds the loaded trackers in
/// one DEX file that the caller mapped read-only from an APK, `length` bytes at `address`. Only the
/// pages the parser touches are read from storage. The result is described on [`scan_result`].
// SAFETY: `no_mangle` exports this function under the JNI-mangled name the JVM resolves for
// `NativeCore.scanMappedDex`. The name is unique within this library, and the signature matches the
// static Kotlin declaration `external fun scanMappedDex(address: Long, length: Int): IntArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_core_NativeCore_scanMappedDex<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    address: jlong,
    length: jint,
) -> JIntArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let (Ok(address), Ok(length)) = (usize::try_from(address), usize::try_from(length))
            else {
                return Err(Error::ParseFailed("invalid DEX mapping".to_owned()));
            };
            if address == 0 {
                return Err(Error::ParseFailed("invalid DEX mapping".to_owned()));
            }
            // SAFETY: the Kotlin caller maps `length` bytes at `address` with `Os.mmap` (read-only,
            // private) and unmaps them only after this call returns, so the memory stays valid and
            // nothing writes to it while the slice exists. It maps only a range that it checked lies
            // within the file, an installed APK, which Android replaces by a new file rather than
            // truncating, so every page stays readable. Bytes need no alignment.
            let bytes = unsafe { std::slice::from_raw_parts(address as *const u8, length) };
            scan_result(env, bytes)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Scans one DEX file with the loaded signatures. The result is `[n, e1..en, r1..rm]`: the number
/// of embedded trackers, their εxodus ids, then the ids of the referenced ones, which include the
/// embedded. A malformed file, or no loaded signatures, is an error that becomes a
/// `RuntimeException`.
fn scan_result<'local>(env: &mut jni::Env<'local>, dex: &[u8]) -> Result<JIntArray<'local>, Error> {
    let signatures = TRACKERS
        .read()
        .ok()
        .and_then(|slot| slot.clone())
        .ok_or_else(|| Error::ParseFailed("no tracker signatures loaded".to_owned()))?;
    let scan = signatures
        .scan_dex(dex)
        .map_err(|e| Error::ParseFailed(e.to_string()))?;
    let to_jint = |id: &u32| jint::try_from(*id).unwrap_or(jint::MAX);
    let mut result = Vec::with_capacity(1 + scan.embedded.len() + scan.referenced.len());
    result.push(jint::try_from(scan.embedded.len()).unwrap_or(jint::MAX));
    result.extend(scan.embedded.iter().map(to_jint));
    result.extend(scan.referenced.iter().map(to_jint));
    let array = JIntArray::new(env, result.len())?;
    array.set_region(env, 0, &result)?;
    Ok(array)
}

/// `org.visadahyu.datapavan.core.NativeCore.readDataPack(byte[], String)`: checks the signature of
/// a data pack against the trusted keys (`signify` public key lines separated by `\n`) and only
/// then reads its header. The result is described on [`pack_layout`].
// SAFETY: `no_mangle` exports this function under the JNI-mangled name the JVM resolves for
// `NativeCore.readDataPack`. The name is unique within this library, and the signature matches the
// static Kotlin declaration `external fun readDataPack(pack: ByteArray, keys: String): IntArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_core_NativeCore_readDataPack<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    pack: JByteArray<'caller>,
    keys: JString<'caller>,
) -> JIntArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let bytes = env.convert_byte_array(&pack)?;
            let keys = keys.try_to_string(env)?;
            let result = keys
                .lines()
                .map(|line| PublicKey::parse(line.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|trusted| datapack::verify(&bytes, &trusted))
                .and_then(|verified| {
                    let payload = bytes.get(verified.payload_start..).unwrap_or_default();
                    Payload::parse(payload).map(|header| (verified, header))
                });
            let fields = match result {
                Ok((verified, header)) => {
                    pack_layout(&header, Some(verified.signer), verified.payload_start)
                }
                Err(error) => vec![error.code()],
            };
            int_array(env, &fields)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `org.visadahyu.datapavan.core.NativeCore.readDataPayload(byte[])`: reads the header of a bare
/// payload, the app's own copy from the APK. The result is described on [`pack_layout`].
// SAFETY: `no_mangle` exports this function under the JNI-mangled name the JVM resolves for
// `NativeCore.readDataPayload`. The name is unique within this library, and the signature matches
// the static Kotlin declaration `external fun readDataPayload(payload: ByteArray): IntArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_core_NativeCore_readDataPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    payload: JByteArray<'caller>,
) -> JIntArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let bytes = env.convert_byte_array(&payload)?;
            let fields = match Payload::parse(&bytes) {
                Ok(header) => pack_layout(&header, None, 0),
                Err(error) => vec![error.code()],
            };
            int_array(env, &fields)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Flattens a pack header for the app. On success: `[0, signer, payloadStart, sequence,
/// dateStart, dateLength, k, k × (start, length), r, r × (start, length), f, f × (pathStart,
/// pathLength, dataStart, dataLength)]`, for the keys, revoked keys and files, where `signer` is
/// the index of the trusted key that signed the pack, or -1 for a bare payload. Every start counts
/// from the beginning of the array the app passed in. On failure, the array holds only the error's
/// code ([`datapack::Error::code`]).
fn pack_layout(header: &Payload, signer: Option<usize>, offset: usize) -> Vec<jint> {
    // Packs are at most 32 MiB, so every number fits.
    let int = |value: usize| jint::try_from(value).unwrap_or(jint::MAX);
    let range = |r: &std::ops::Range<usize>| [int(offset + r.start), int(r.len())];
    let mut out = vec![
        0,
        signer.map_or(-1, int),
        int(offset),
        jint::try_from(header.sequence).unwrap_or(jint::MAX),
    ];
    out.extend(range(&header.date));
    for list in [&header.keys, &header.revoked] {
        out.push(int(list.len()));
        out.extend(list.iter().flat_map(range));
    }
    out.push(int(header.files.len()));
    for file in &header.files {
        out.extend(range(&file.path));
        out.extend(range(&file.data));
    }
    out
}

fn int_array<'local>(
    env: &mut jni::Env<'local>,
    values: &[jint],
) -> Result<JIntArray<'local>, Error> {
    let array = JIntArray::new(env, values.len())?;
    array.set_region(env, 0, values)?;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use datapavan_engine::attestation::{KeyDescription, RootOfTrust};

    /// The record `AttestationFieldsTest` in the app decodes: the two tests hold the layout to one
    /// reading on both sides of the bridge.
    const RECORD: &str = concat!(
        "01",
        "000000000000012c",
        "0000000000000001",
        "0000000000000001",
        "0000000000000001",
        "0000000000027100",
        "000000000003170b",
        "0000000000031706",
        "ffffffffffffffff",
        "00000003",
        "616263",
        "00000002",
        "aabb",
        "ffffffff",
    );

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn encodes_the_record_the_app_decodes() {
        let description = KeyDescription {
            attestation_version: 300,
            security_level: SecurityLevel::TrustedEnvironment,
            attestation_challenge: b"abc",
            root_of_trust: Some(RootOfTrust {
                verified_boot_key: &[0xaa, 0xbb],
                device_locked: true,
                verified_boot: VerifiedBootState::SelfSigned,
                verified_boot_hash: None,
            }),
            os_version: Some(160_000),
            os_patch_level: Some(202_507),
            vendor_patch_level: Some(202_502),
            boot_patch_level: None,
        };
        assert_eq!(hex(&encode(&description)), RECORD);
    }

    #[test]
    fn encodes_every_level_and_boot_state() {
        let level_and_boot = |level, boot| {
            let description = KeyDescription {
                attestation_version: 1,
                security_level: level,
                attestation_challenge: &[],
                root_of_trust: Some(RootOfTrust {
                    verified_boot_key: &[],
                    device_locked: false,
                    verified_boot: boot,
                    verified_boot_hash: Some(&[]),
                }),
                os_version: None,
                os_patch_level: None,
                vendor_patch_level: None,
                boot_patch_level: None,
            };
            // The last byte of the level, deviceLocked and verifiedBoot integers.
            let record = encode(&description);
            (
                record.get(16).copied(),
                record.get(24).copied(),
                record.get(32).copied(),
            )
        };
        for (level, value) in [
            (SecurityLevel::Software, 0),
            (SecurityLevel::TrustedEnvironment, 1),
            (SecurityLevel::StrongBox, 2),
        ] {
            assert_eq!(
                level_and_boot(level, VerifiedBootState::Verified).0,
                Some(value)
            );
        }
        for (boot, value) in [
            (VerifiedBootState::Verified, 0),
            (VerifiedBootState::SelfSigned, 1),
            (VerifiedBootState::Unverified, 2),
            (VerifiedBootState::Failed, 3),
        ] {
            let (_, locked, state) = level_and_boot(SecurityLevel::Software, boot);
            assert_eq!((locked, state), (Some(0), Some(value)));
        }
    }
}
