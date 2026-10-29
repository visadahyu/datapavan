//! Prints the trackers found in an app's DEX files, as Datapavan's scanner finds them: first the
//! trackers whose classes the app contains, then those it only refers to.
//!
//! ```sh
//! cargo run --release --example scan_trackers -- data/exodus/trackers.tsv classes.dex [classes2.dex ...]
//! ```

use datapavan_engine::{dex, trackers::Signatures};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(signatures) = args
        .next()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|tsv| Signatures::parse(&tsv).ok())
    else {
        eprintln!("usage: scan_trackers trackers.tsv classes.dex [classes2.dex ...]");
        return ExitCode::FAILURE;
    };
    let (mut defined, mut referenced) = (Vec::new(), Vec::new());
    for path in args {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("{path}: {error}");
                return ExitCode::FAILURE;
            }
        };
        match (
            dex::defined_classes(&bytes),
            dex::referenced_classes(&bytes),
        ) {
            (Ok(d), Ok(r)) => {
                defined.extend(d);
                referenced.extend(r);
            }
            (Err(error), _) | (_, Err(error)) => {
                eprintln!("{path}: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    let embedded = signatures.find(defined.iter().map(String::as_str));
    let mentioned = signatures.find(referenced.iter().map(String::as_str));
    for (kind, found) in [("embedded", &embedded), ("referenced", &mentioned)] {
        for &index in found {
            if kind == "referenced" && embedded.contains(&index) {
                continue;
            }
            if let Some(tracker) = signatures.trackers().get(index) {
                println!("{kind}\t{}\t{}", tracker.id, tracker.name);
            }
        }
    }
    ExitCode::SUCCESS
}
