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
    //
    // And lld folds identical functions into one copy (--icf=all): 11,024 bytes more on 2026-11-24, the maintainer's
    // word. "all", since "safe" folds nothing here: no object of the link, Rust's or aws-lc's, carries an
    // address-significance table. Only code is folded, never data: lld keeps every data section unique for an object
    // without that table, so distinct statics keep distinct addresses. The risk: two functions with the same machine
    // code get one address, so C code that compared function addresses would take them for one. Rust does not promise
    // distinct addresses to functions; of aws-lc, lld folds today an empty AEAD cleanup, two mutex functions and
    // jitterentropy's free, whose addresses aws-lc never takes, but the cleanup's, which it compares with NULL alone.
    // An upgrade of aws-lc or GotaTun links once with -Wl,--print-icf-sections and reads every fold from an object
    // that is not Rust's (ADR 0053, the size pass).
    if std::env::var("PROFILE").as_deref() == Ok("release")
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        println!("cargo::rustc-cdylib-link-arg=-Wl,--no-eh-frame-hdr");
        println!("cargo::rustc-cdylib-link-arg=-Wl,--icf=all");
    }
}
