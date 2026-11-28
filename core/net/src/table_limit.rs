//! The one size limit of the tables compiled into the engine (the cold paths' fourth pass, ADR 0053): `build.rs`
//! refuses a table that is not below it, and `crate::bundled` inflates no more than it. One file, which both read, so
//! that the two cannot differ.

/// The most bytes a table compiled into the engine may hold: 256 KiB, the largest today 14,886
/// (`data/resolvers/resolvers.tsv`).
pub const TABLE_LIMIT: usize = 256 * 1024;
