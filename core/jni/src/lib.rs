//! Thin JNI bridge between the Android app and [`datapavan_engine`].
//!
//! Every export here is a boundary where data crosses between the JVM and Rust. Keep each one
//! small: convert the arguments, call the engine, convert the result. All logic belongs in the
//! engine crate, which contains no unsafe code.
//!
//! Errors are turned into a Java `RuntimeException` by the chosen error policy. In debug builds,
//! `EnvUnowned::with_env` catches panics so they never unwind into the JVM; release builds use
//! `panic = "abort"`, which ends the process first.

use jni::EnvUnowned;
use jni::errors::{Error, ThrowRuntimeExAndDefault};
use jni::objects::{JClass, JString};

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
