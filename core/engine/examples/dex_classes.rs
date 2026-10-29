//! Prints the classes that each given DEX file defines, one Java name per line, in the order of the
//! file's `class_defs`. `scripts/compare-dex.sh` compares this with `dexdump` on real apps.
//!
//! ```sh
//! cargo run --release --example dex_classes -- classes.dex [classes2.dex ...]
//! ```

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut status = ExitCode::SUCCESS;
    for path in std::env::args().skip(1) {
        match std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                datapavan_engine::dex::defined_classes(&bytes).map_err(|e| e.to_string())
            }) {
            Ok(classes) => {
                for class in classes {
                    println!("{class}");
                }
            }
            Err(error) => {
                eprintln!("{path}: {error}");
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}
