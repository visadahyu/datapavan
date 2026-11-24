//! A link setting of the network part's library that Gradle's flags cannot give one ABI alone: cargo-ndk builds the
//! three ABIs in one call, with one set of flags (android/network/build.gradle.kts), and those flags override any
//! flags for one target in Cargo's configuration.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    // The release library for x86_64 only, the ABI nearest its 2 MiB gate (scripts/check.sh, native_budget): lld
    // writes no .eh_frame_hdr, the sorted index of the unwind tables (24,652 bytes; leaving it out saved 24,848 of the
    // library's 2,082,648 on 2026-11-24, ADR 0053, "Size", the size pass). The unwind tables themselves stay: Android's
    // debuggerd finds them through the section headers and reads them without the index, so a crash's tombstone keeps
    // its frames. Nothing in a release build unwinds its own stack, since a panic there aborts (core/Cargo.toml).
    // A debug build unwinds a panic into a Java exception (the jni crate's catch_unwind), and the unwinder linked into
    // the library looks for the tables through the index's program header: debug builds keep it. PROFILE, not CARGO_CFG_PANIC, tells
    // them apart: Cargo gives build scripts the target's default strategy, "unwind", whatever the profile says. arm64
    // and armv7 keep the index: they have room.
    if std::env::var("PROFILE").as_deref() == Ok("release")
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        println!("cargo::rustc-cdylib-link-arg=-Wl,--no-eh-frame-hdr");
    }
}
