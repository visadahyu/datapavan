//! Datapavan engine.
//!
//! Platform-independent logic shared by every Datapavan host: the Android app today, the
//! Device Owner flavour and a system daemon later. Untrusted input (packets, DEX files) is
//! parsed here, so this crate must never contain `unsafe` code. The workspace lint
//! configuration enforces that at compile time.

pub mod attestation;

/// Version of the engine, taken from the crate manifest at build time.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert_ne!(version(), "");
    }
}
