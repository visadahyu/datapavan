//! The tables compiled into the engine, deflated (the cold paths' fourth pass, ADR 0053): each of the six files the
//! engine reads at its start is checked, deflated and written to `OUT_DIR`, where `include_bytes!` takes it, and
//! `crate::bundled` inflates it where it is parsed. A table is refused, and the build fails, when it is not UTF-8
//! (which `include_str!` refused before), when it is not below the one limit `bundled` inflates to
//! (`src/table_limit.rs`, read by both), or when its blob does not inflate back to it through `bundled`'s own call:
//! release builds compile no test, so this is where a table the engine could not read is stopped. Raw DEFLATE at a
//! fixed level holds no time, name or path, so the same file gives the same blob in every build.
//!
//! The six files are listed in three more places, to be kept with this one: the modules' test-only text constants
//! (`src/owners.rs`, `src/resolvers.rs`, `src/messengers.rs`), the native build's inputs in Gradle
//! (`android/network/build.gradle.kts`, `CargoNdkTask`'s sources) and `scripts/ci-scope.sh`'s `data_tier`, which
//! sends their changes to the emulator (the owners' two as every bundled dataset's).

#[path = "src/table_limit.rs"]
mod table_limit;

use std::path::Path;

/// The six tables, each by its dataset and file under `data/`: the blob's name is both, so that two datasets' files
/// of one name never share a blob.
const TABLES: [(&str, &str); 6] = [
    ("owners", "entities.tsv"),
    ("owners", "asns.tsv"),
    ("resolvers", "resolvers.tsv"),
    ("messengers", "telegram-cidr.txt"),
    ("messengers", "clients.tsv"),
    ("messengers", "names.tsv"),
];

/// DEFLATE's highest level in `miniz_oxide`: the smallest blobs, and fixed, so that the blobs do not change between
/// builds.
const LEVEL: u8 = 10;

fn main() -> Result<(), String> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/table_limit.rs");
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR is not set")?;
    let out = std::env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?;
    let data = Path::new(&manifest).join("../../data");
    for (dataset, file) in TABLES {
        let source = data.join(dataset).join(file);
        println!("cargo::rerun-if-changed={}", source.display());
        let raw = std::fs::read(&source).map_err(|e| format!("{}: {e}", source.display()))?;
        std::str::from_utf8(&raw).map_err(|e| format!("{}: not UTF-8: {e}", source.display()))?;
        if raw.len() >= table_limit::TABLE_LIMIT {
            return Err(format!(
                "{}: {} bytes, not below the limit of {} (src/table_limit.rs)",
                source.display(),
                raw.len(),
                table_limit::TABLE_LIMIT
            ));
        }
        let blob = miniz_oxide::deflate::compress_to_vec(&raw, LEVEL);
        let back =
            miniz_oxide::inflate::decompress_to_vec_with_limit(&blob, table_limit::TABLE_LIMIT)
                .map_err(|e| format!("{}: the blob does not inflate: {e:?}", source.display()))?;
        if back != raw {
            return Err(format!(
                "{}: the blob inflates to other bytes",
                source.display()
            ));
        }
        let blob_path = Path::new(&out).join(format!("{dataset}-{file}.deflate"));
        std::fs::write(&blob_path, blob).map_err(|e| format!("{}: {e}", blob_path.display()))?;
    }
    Ok(())
}
