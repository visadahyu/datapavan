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
use jni::EnvUnowned;
use jni::errors::{Error, ThrowRuntimeExAndDefault};
use jni::objects::{JByteArray, JClass, JLongArray, JString};

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
/// it. The result is `[attestationVersion, securityLevel, deviceLocked, verifiedBoot, osPatchLevel]`,
/// with -1 for an absent value; malformed input throws a `RuntimeException`.
// SAFETY: `no_mangle` exports this function under the JNI-mangled name the JVM resolves for
// `NativeCore.parseAttestation`. The name is unique within this library, and the signature matches
// the static Kotlin declaration `external fun parseAttestation(extension: ByteArray): LongArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_core_NativeCore_parseAttestation<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    extension: JByteArray<'caller>,
) -> JLongArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let bytes = env.convert_byte_array(&extension)?;
            let description = attestation::parse_key_description(&bytes)
                .map_err(|e| Error::ParseFailed(e.to_string()))?;
            let fields = encode(&description);
            let array = JLongArray::new(env, fields.len())?;
            array.set_region(env, 0, &fields)?;
            Ok(array)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Flattens a `KeyDescription` into the array layout documented on the export above.
fn encode(description: &attestation::KeyDescription) -> [i64; 5] {
    let level = match description.security_level {
        SecurityLevel::Software => 0,
        SecurityLevel::TrustedEnvironment => 1,
        SecurityLevel::StrongBox => 2,
    };
    let (locked, boot) = description.root_of_trust.map_or((-1, -1), |root| {
        let boot = match root.verified_boot {
            VerifiedBootState::Verified => 0,
            VerifiedBootState::SelfSigned => 1,
            VerifiedBootState::Unverified => 2,
            VerifiedBootState::Failed => 3,
        };
        (i64::from(root.device_locked), boot)
    });
    let patch = description.os_patch_level.map_or(-1, i64::from);
    [
        i64::from(description.attestation_version),
        level,
        locked,
        boot,
        patch,
    ]
}
