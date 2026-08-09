//! `bellbook validate <file>` - offline receipt validation for auditors.
//!
//! Exit codes: 0 = clean, 1 = invalid, 2 = valid but contains
//! retracted/tainted claims, 64 = usage error, 66 = unreadable input.

use bellbook::receipt::{validate_with_limits, ValidationLimits, ValidationStatus};
use std::process::ExitCode;

/// Default cap on receipt file size: 64 MiB. Far above any realistic
/// honest receipt; prevents a hostile file from demanding unbounded
/// memory. Override with --max-size (0 = unlimited).
const DEFAULT_MAX_SIZE: u64 = 64 << 20;

const USAGE: &str = "\
bellbook - accountability-ledger tools

USAGE:
    bellbook validate <receipt-file> [--json] [--max-size <bytes>]

COMMANDS:
    validate    Verify a receipt offline: ids (RFC 8785 canonical form),
                gap-free logical time, verdict re-derivation, signatures,
                evidence derivation, and taint status.

OPTIONS:
    --json               Emit the full report as JSON instead of
                         human-readable text.
    --max-size <bytes>   Refuse receipt files larger than this before
                         reading them (default 67108864 = 64 MiB;
                         0 = unlimited). The CLI is the trust boundary
                         for untrusted receipts, so the bound is applied
                         here, not upstream.

EXIT CODES:
    0    clean - the log verified and contains no retracted/tainted claims
    1    invalid - the receipt failed verification (details in the report)
    2    tainted - valid history, but some claims are retracted or tainted
    64   usage error
    66   input file unreadable
    70   internal error (report serialization failed)\
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let (command, rest) = match args.split_first() {
        Some((c, rest)) => (c.as_str(), rest),
        None => {
            eprintln!("{USAGE}");
            return ExitCode::from(64);
        }
    };
    if command != "validate" {
        eprintln!("unknown command {command:?}\n\n{USAGE}");
        return ExitCode::from(64);
    }

    let mut file: Option<&str> = None;
    let mut json = false;
    let mut max_size = DEFAULT_MAX_SIZE;
    let mut args_iter = rest.iter();
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--max-size" => {
                let Some(value) = args_iter.next() else {
                    eprintln!("--max-size requires a value\n\n{USAGE}");
                    return ExitCode::from(64);
                };
                match value.parse::<u64>() {
                    Ok(0) => max_size = u64::MAX,
                    Ok(n) => max_size = n,
                    Err(_) => {
                        eprintln!("invalid --max-size value {value:?}\n\n{USAGE}");
                        return ExitCode::from(64);
                    }
                }
            }
            other if file.is_none() && !other.starts_with('-') => file = Some(other),
            other => {
                eprintln!("unexpected argument {other:?}\n\n{USAGE}");
                return ExitCode::from(64);
            }
        }
    }
    let Some(path) = file else {
        eprintln!("missing <receipt-file>\n\n{USAGE}");
        return ExitCode::from(64);
    };

    // Bounded read: the file is untrusted input and this process is the
    // trust boundary. Reading through `take(max_size + 1)` enforces the
    // bound on the bytes actually read - a size check on metadata alone
    // would race against the file growing between check and read.
    let bytes = {
        use std::io::Read;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("cannot read {path}: {e}");
                return ExitCode::from(66);
            }
        };
        let cap = max_size.saturating_add(1);
        let mut buf = Vec::new();
        if let Err(e) = file.take(cap).read_to_end(&mut buf) {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(66);
        }
        if buf.len() as u64 > max_size {
            eprintln!("refusing {path}: exceeds --max-size {max_size} bytes");
            return ExitCode::from(66);
        }
        buf
    };

    let limits = ValidationLimits {
        max_bytes: usize::try_from(max_size).unwrap_or(usize::MAX),
        ..ValidationLimits::default()
    };
    let report = validate_with_limits(&bytes, &limits);

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("cannot serialize report: {e}");
                return ExitCode::from(70);
            }
        }
    } else {
        print!("{report}");
    }

    match report.status {
        ValidationStatus::Clean => ExitCode::SUCCESS,
        ValidationStatus::Invalid => ExitCode::from(1),
        ValidationStatus::Tainted => ExitCode::from(2),
    }
}
