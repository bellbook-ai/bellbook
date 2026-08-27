//! `bellbook` - accountability-ledger CLI.
//!
//! `validate <receipt>` verifies a receipt offline (feature-independent). The
//! evolution subcommands (`candidate`, `eval`, `select`, `lineage`) are thin
//! wrappers over the crate that operate on a persistent log and therefore need
//! the `persist` feature; JSON in/out, and every mutating command prints the
//! committed record id.
//!
//! **Concurrency (SPEC §5.1):** the persistent log is deliberately
//! single-writer - `LogWriter` holds an exclusive lock. Parallel candidate
//! *generation* is the intended workload; parallel *recording* is not. Generate
//! candidates concurrently, then record them serially in one process (a loop,
//! or `checked_batch_commit` for retry-safe batches). The CLI is not a
//! coordination layer.
//!
//! Exit codes: 0 = success/clean, 1 = invalid receipt, 2 = valid but
//! retracted/tainted, 64 = usage error, 65 = command failed (e.g. a rejected
//! record), 66 = unreadable input, 70 = internal error.

use bellbook::*;
use std::process::ExitCode;

/// Default cap on receipt file size: 64 MiB.
const DEFAULT_MAX_SIZE: u64 = 64 << 20;

const USAGE: &str = "\
bellbook - accountability-ledger tools

USAGE:
    bellbook validate <receipt-file> [--json] [--max-size <bytes>]
    bellbook candidate add --log <dir> --rules <file> --author <id>
                           --git-tree <oid> [--git-commit <oid>] [--algo sha1|sha256]
                           [--manifest <path-to-tree>]
                           [--continues <selection-id> --parent <candidate-id>
                            | --derives-from <id> ...
                            | --upgrades <candidate-id>]
                           [--note <s>] [--json]
    bellbook eval add      --log <dir> --rules <file> --author <id>
                           --candidate <id> --criterion <s>
                           (--passed | --failed | --score <value> --scale <n>)
                           [--procedure <s>] [--uses <id> ...] [--json]
    bellbook select        --log <dir> --rules <file> --author <id>
                           --objective <s> --consider <id> ...
                           (--choose <id> ... --uses-eval <id> ... | --none)
                           [--replaces <selection-id>] [--rationale <s>] [--json]
    bellbook retract       --log <dir> --rules <file> --author <id>
                           --target <record-id> --reason <text> [--json]
    bellbook lineage       --log <dir> --rules <file> <id> [--json]
    bellbook rules init    --author <id>:<role> ... [--admin <id>] ... [--reaffirmer <id>] ...
                           [--max-context <n>] [--out <file>]
    bellbook export        --log <dir> --rules <file> [--out <file>]

COMMANDS:
    validate    Verify a receipt offline: ids (RFC 8785 canonical form),
                gap-free logical time, verdict re-derivation, signatures,
                evidence derivation, taint, and the standing section.
    candidate   Record a Candidate (a proposed source state).
    eval        Record an Evaluation of a candidate.
    select      Record a Selection over candidates (or a reaffirmation).
    retract     Assert a committed record's content is wrong. The target
                stays in the log; the receipt reports Tainted from then on.
                Accepted only from the target's author or an admin actor.
    lineage     Show a candidate's descent, siblings, taint, and standing.
    rules init  Generate a starter verifier-rules file. Roles are one of
                user|provider|system|executor|verifier. --admin allows an
                actor to retract records it did not author; --reaffirmer
                restricts reaffirming selections to the listed actors.
    export      Bundle a log directory into a portable receipt (the input
                `bellbook validate` verifies).

EXIT CODES:
    0 clean/success   1 invalid   2 tainted   64 usage   65 command failed
    66 unreadable input   70 internal error\
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = match args.split_first() {
        Some((c, rest)) => (c.as_str(), rest.to_vec()),
        None => {
            eprintln!("{USAGE}");
            return ExitCode::from(64);
        }
    };
    match command {
        "validate" => cmd_validate(&rest),
        "rules" => cmd_rules(&rest),
        "candidate" | "eval" | "select" | "retract" | "lineage" | "export" => {
            cmd_evolution(command, &rest)
        }
        other => {
            eprintln!("unknown command {other:?}\n\n{USAGE}");
            ExitCode::from(64)
        }
    }
}

// ---------------------------------------------------------------------------
// rules init (feature-independent)
// ---------------------------------------------------------------------------

fn parse_role(s: &str) -> Option<AuthorType> {
    match s.to_ascii_lowercase().as_str() {
        "user" => Some(AuthorType::User),
        "provider" => Some(AuthorType::Provider),
        "system" => Some(AuthorType::System),
        "executor" => Some(AuthorType::Executor),
        "verifier" => Some(AuthorType::Verifier),
        _ => None,
    }
}

/// `rules init` writes a starter verifier-rules file: the default space, a
/// context bound, one author-role binding per `--author <id>:<role>`, and
/// optionally the two retraction-story knobs - `--admin <id>` (may retract
/// records it did not author) and `--reaffirmer <id>` (restricts reaffirming
/// selections to the listed actors). It is the trust policy the CLI's
/// `--rules` flag and the receipt embed; generating one by hand is the main
/// ceremony a new user hits, so this removes it.
fn cmd_rules(rest: &[String]) -> ExitCode {
    let (sub, rest) = match rest.split_first() {
        Some((s, r)) => (s.as_str(), r),
        None => {
            eprintln!("rules needs a subcommand (init)\n\n{USAGE}");
            return ExitCode::from(64);
        }
    };
    if sub != "init" {
        eprintln!("unknown rules subcommand {sub:?} (expected init)\n\n{USAGE}");
        return ExitCode::from(64);
    }

    let mut authors: Vec<(String, AuthorType)> = Vec::new();
    let mut admins: Vec<String> = Vec::new();
    let mut reaffirmers: Vec<String> = Vec::new();
    let mut max_context: u32 = 200;
    let mut out: Option<String> = None;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--admin" => {
                let Some(v) = it.next() else {
                    eprintln!("--admin requires an actor id");
                    return ExitCode::from(64);
                };
                if v.is_empty() {
                    eprintln!("--admin id must be non-empty");
                    return ExitCode::from(64);
                }
                admins.push(v.clone());
            }
            "--reaffirmer" => {
                let Some(v) = it.next() else {
                    eprintln!("--reaffirmer requires an actor id");
                    return ExitCode::from(64);
                };
                if v.is_empty() {
                    eprintln!("--reaffirmer id must be non-empty");
                    return ExitCode::from(64);
                }
                reaffirmers.push(v.clone());
            }
            "--author" => {
                let Some(v) = it.next() else {
                    eprintln!("--author requires <id>:<role>");
                    return ExitCode::from(64);
                };
                let Some((id, role)) = v.split_once(':') else {
                    eprintln!("--author must be <id>:<role>, got {v:?}");
                    return ExitCode::from(64);
                };
                if id.is_empty() {
                    eprintln!("--author id must be non-empty");
                    return ExitCode::from(64);
                }
                let Some(role) = parse_role(role) else {
                    eprintln!("invalid role {role:?} (user|provider|system|executor|verifier)");
                    return ExitCode::from(64);
                };
                authors.push((id.to_string(), role));
            }
            "--max-context" => {
                let Some(v) = it.next() else {
                    eprintln!("--max-context requires a value");
                    return ExitCode::from(64);
                };
                match v.parse::<u32>() {
                    Ok(n) => max_context = n,
                    Err(_) => {
                        eprintln!("invalid --max-context value {v:?}");
                        return ExitCode::from(64);
                    }
                }
            }
            "--out" => {
                let Some(v) = it.next() else {
                    eprintln!("--out requires a path");
                    return ExitCode::from(64);
                };
                out = Some(v.clone());
            }
            other => {
                eprintln!("unexpected argument {other:?}\n\n{USAGE}");
                return ExitCode::from(64);
            }
        }
    }

    if authors.is_empty() {
        eprintln!("rules init needs at least one --author <id>:<role>");
        return ExitCode::from(64);
    }

    // An admin or reaffirmer with no role binding could never author an
    // accepted record, so the flag would be a silent no-op; refuse instead.
    for (flag, ids) in [("--admin", &admins), ("--reaffirmer", &reaffirmers)] {
        for id in ids {
            if !authors.iter().any(|(a, _)| a == id) {
                eprintln!("{flag} {id:?} has no --author {id}:<role> binding; add one");
                return ExitCode::from(64);
            }
        }
    }

    let mut rules = VerifierRules::new(default_space(), max_context);
    for (id, role) in authors {
        rules = rules.with_author_role(id, role);
    }
    for id in admins {
        rules = rules.with_admin_retraction_actor(id);
    }
    for id in reaffirmers {
        rules = rules.with_reaffirmation_actor(id);
    }
    let json = match serde_json::to_string(&rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot serialize rules: {e}");
            return ExitCode::from(70);
        }
    };
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, json.as_bytes()) {
                eprintln!("cannot write {path}: {e}");
                return ExitCode::from(66);
            }
            // The data output is the file; a confirmation goes to stderr.
            eprintln!("wrote starter rules to {path}");
        }
        None => println!("{json}"),
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// validate (feature-independent)
// ---------------------------------------------------------------------------

fn cmd_validate(rest: &[String]) -> ExitCode {
    let mut file: Option<&str> = None;
    let mut json = false;
    let mut max_size = DEFAULT_MAX_SIZE;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--max-size" => {
                let Some(v) = it.next() else {
                    eprintln!("--max-size requires a value\n\n{USAGE}");
                    return ExitCode::from(64);
                };
                match v.parse::<u64>() {
                    Ok(0) => max_size = u64::MAX,
                    Ok(n) => max_size = n,
                    Err(_) => {
                        eprintln!("invalid --max-size value {v:?}");
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

#[cfg(not(feature = "persist"))]
fn cmd_evolution(command: &str, _rest: &[String]) -> ExitCode {
    eprintln!("the {command:?} command requires the `persist` feature (build without --no-default-features)");
    ExitCode::from(64)
}

#[cfg(feature = "persist")]
fn cmd_evolution(command: &str, rest: &[String]) -> ExitCode {
    let result = match command {
        "candidate" => persist_cmds::candidate(rest),
        "eval" => persist_cmds::eval(rest),
        "select" => persist_cmds::select(rest),
        "retract" => persist_cmds::retract(rest),
        "lineage" => persist_cmds::lineage(rest),
        "export" => persist_cmds::export(rest),
        _ => unreachable!(),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(65)
        }
    }
}

#[cfg(feature = "persist")]
mod persist_cmds {
    use bellbook::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::process::ExitCode;

    /// A parsed flag set: single-value flags, repeatable multi-value flags,
    /// boolean flags, and bare positionals. Multi-value flags consume every
    /// following token up to the next `--flag`.
    struct Parsed {
        singles: BTreeMap<String, String>,
        multis: BTreeMap<String, Vec<String>>,
        bools: BTreeSet<String>,
        positionals: Vec<String>,
    }

    /// Parse `--flag` arguments against the declared flag names for a
    /// subcommand. `singles` take one value, `multi` repeat/consume a run of
    /// values, `bools` take none. An unrecognized `--flag` is an error (so a
    /// typo like `--auther` is caught, not silently treated as a value slot),
    /// a single-value flag whose next token is itself a declared flag is a
    /// missing-value error (so `--procedure --passed` cannot silently swallow
    /// `--passed`), and a single-value flag given twice is an error rather
    /// than silently last-wins.
    fn parse(
        rest: &[String],
        singles: &[&str],
        multi: &[&str],
        bools: &[&str],
    ) -> Result<Parsed, String> {
        let mut p = Parsed {
            singles: BTreeMap::new(),
            multis: BTreeMap::new(),
            bools: BTreeSet::new(),
            positionals: Vec::new(),
        };
        let is_flag = |t: &str| {
            t.strip_prefix("--")
                .is_some_and(|n| singles.contains(&n) || multi.contains(&n) || bools.contains(&n))
        };
        let mut i = 0;
        while i < rest.len() {
            let tok = &rest[i];
            if let Some(name) = tok.strip_prefix("--") {
                if bools.contains(&name) {
                    p.bools.insert(name.to_string());
                    i += 1;
                } else if multi.contains(&name) {
                    let mut vals = Vec::new();
                    i += 1;
                    while i < rest.len() && !rest[i].starts_with("--") {
                        vals.push(rest[i].clone());
                        i += 1;
                    }
                    if vals.is_empty() {
                        return Err(format!("--{name} requires at least one value"));
                    }
                    p.multis.entry(name.to_string()).or_default().extend(vals);
                } else if singles.contains(&name) {
                    let Some(v) = rest.get(i + 1) else {
                        return Err(format!("--{name} requires a value"));
                    };
                    if is_flag(v) {
                        return Err(format!("--{name} requires a value (found flag {v})"));
                    }
                    if p.singles.insert(name.to_string(), v.clone()).is_some() {
                        return Err(format!("--{name} specified more than once"));
                    }
                    i += 2;
                } else {
                    return Err(format!("unknown flag --{name}"));
                }
            } else {
                p.positionals.push(tok.clone());
                i += 1;
            }
        }
        Ok(p)
    }

    fn require<'a>(p: &'a Parsed, key: &str) -> Result<&'a str, String> {
        p.singles
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("missing required --{key}"))
    }

    fn load_rules(p: &Parsed) -> Result<VerifierRules, String> {
        let path = require(p, "rules")?;
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read rules {path}: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("cannot parse rules {path}: {e}"))
    }

    /// Open the log and rebuild verified state from its committed records.
    fn open(p: &Parsed, rules: &VerifierRules) -> Result<(LogWriter, State), String> {
        let dir = require(p, "log")?;
        let writer =
            LogWriter::open(std::path::Path::new(dir), rules).map_err(|e| format!("{e:?}"))?;
        let state = verify_and_build_state(writer.records(), rules)
            .map_err(|_| "the existing log does not verify under these rules".to_string())?;
        Ok((writer, state))
    }

    fn author(rules: &VerifierRules, p: &Parsed) -> Result<Author, String> {
        let id = require(p, "author")?;
        let type_ =
            rules.author_roles.get(id).copied().ok_or_else(|| {
                format!("author {id:?} is not registered in the rules' author_roles")
            })?;
        Ok(Author {
            id: id.to_string(),
            type_,
            signature: None,
        })
    }

    fn parse_id(hex: &str) -> Result<RecordId, String> {
        hex_decode(hex).ok_or_else(|| format!("invalid record id {hex:?}"))
    }

    /// Look up an accepted Candidate by id and decode its payload.
    fn find_candidate(records: &[Record], id: RecordId) -> Option<CandidateData> {
        records
            .iter()
            .find(|r| r.id == id && r.kind == Kind::Candidate)
            .and_then(|r| decode::<CandidateData>(&r.data).ok())
    }

    fn manifest_binding(path: &str) -> Result<Hash256, String> {
        let entries = manifest_from_dir(std::path::Path::new(path), &BTreeMap::new())
            .map_err(|e| format!("cannot walk tree {path}: {e}"))?;
        manifest_hash(&entries).ok_or_else(|| "manifest has duplicate paths".to_string())
    }

    /// Encode a payload, then decode it back to run the same invariant checks
    /// the verifier applies (score bounds, non-empty criterion/objective, ...).
    /// This turns a statically-knowable payload violation into a clean
    /// pre-commit error instead of a durable rejected record with an opaque
    /// reason: `encode` is a bare serialization and never runs the `TryFrom`
    /// bound checks, so without this round-trip a `--scale 13` would serialize,
    /// commit, and only then reject.
    fn checked_encode<T>(value: &T) -> Result<Vec<u8>, String>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let bytes = encode(value).map_err(|e| format!("{e}"))?;
        decode::<T>(&bytes).map_err(|e| format!("invalid payload: {e}"))?;
        Ok(bytes)
    }

    #[derive(serde::Serialize)]
    struct CommitOutput {
        id: String,
        result: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    }

    /// Commit a proposal, print its id, and map the verdict to an exit code.
    fn commit_and_print(
        mut writer: LogWriter,
        rules: &VerifierRules,
        mut state: State,
        proposal: Proposal,
        json: bool,
    ) -> Result<ExitCode, String> {
        let (id, verdict) = writer
            .commit(proposal, rules, &mut state)
            .map_err(|e| format!("commit failed: {e:?}"))?;
        let accepted = verdict.result == VerdictResult::Accept;
        let out = CommitOutput {
            id: hex_encode(&id),
            result: if accepted { "accept" } else { "reject" }.to_string(),
            reason: verdict.reason.map(|r| format!("{r:?}")),
        };
        if json {
            println!(
                "{}",
                serde_json::to_string(&out).map_err(|e| format!("{e}"))?
            );
        } else if accepted {
            println!("{}", out.id);
        } else {
            // A rejection is a diagnostic, not the command's data output.
            eprintln!(
                "{} rejected: {}",
                out.id,
                out.reason.as_deref().unwrap_or("?")
            );
        }
        Ok(if accepted {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(65)
        })
    }

    // --- export ------------------------------------------------------------

    /// Bundle a log directory into a portable receipt. `open` rebuilds and
    /// re-verifies state from the committed records, so a log that does not
    /// verify under the given rules is refused before anything is written.
    pub fn export(rest: &[String]) -> Result<ExitCode, String> {
        let p = parse(rest, &["log", "rules", "out"], &[], &[])?;
        let rules = load_rules(&p)?;
        let (writer, _state) = open(&p, &rules)?;
        let bytes = Receipt::new(writer.records(), &rules)
            .to_bytes()
            .map_err(|e| format!("cannot serialize receipt: {e}"))?;
        match p.singles.get("out") {
            Some(path) => {
                std::fs::write(path, &bytes).map_err(|e| format!("cannot write {path}: {e}"))?;
                eprintln!("wrote receipt to {path} ({} bytes)", bytes.len());
            }
            None => {
                use std::io::Write;
                std::io::stdout()
                    .write_all(&bytes)
                    .map_err(|e| format!("cannot write receipt to stdout: {e}"))?;
            }
        }
        Ok(ExitCode::SUCCESS)
    }

    // --- candidate add -----------------------------------------------------

    pub fn candidate(rest: &[String]) -> Result<ExitCode, String> {
        let (sub, rest) = rest
            .split_first()
            .ok_or_else(|| "candidate needs a subcommand (add)".to_string())?;
        if sub != "add" {
            return Err(format!(
                "unknown candidate subcommand {sub:?} (expected add)"
            ));
        }
        let p = parse(
            rest,
            &[
                "log",
                "rules",
                "author",
                "git-tree",
                "git-commit",
                "algo",
                "note",
                "manifest",
                "continues",
                "parent",
                "upgrades",
            ],
            &["derives-from"],
            &["json"],
        )?;
        let rules = load_rules(&p)?;
        let (writer, state) = open(&p, &rules)?;
        let author = author(&rules, &p)?;

        let algo = match p.singles.get("algo").map(String::as_str) {
            None | Some("sha1") => SourceAlgo::Sha1,
            Some("sha256") => SourceAlgo::Sha256,
            Some(other) => return Err(format!("invalid --algo {other:?}")),
        };
        let tree = require(&p, "git-tree")?.to_string();
        let commit = p.singles.get("git-commit").cloned();
        let note = p.singles.get("note").cloned();

        // Basis selection is mutually exclusive.
        let continues = p.singles.get("continues");
        let derives = p.multis.get("derives-from");
        let upgrades = p.singles.get("upgrades");
        let n_basis = [continues.is_some(), derives.is_some(), upgrades.is_some()]
            .iter()
            .filter(|b| **b)
            .count();
        if n_basis > 1 {
            return Err(
                "--continues, --derives-from, and --upgrades are mutually exclusive".into(),
            );
        }
        // `--parent` names the continued-from candidate and is meaningful only
        // for a continuation; silently dropping it elsewhere would lose stated
        // intent, so reject it instead.
        if continues.is_none() && p.singles.contains_key("parent") {
            return Err("--parent is only valid with --continues".into());
        }

        let (basis, parent, refs) = if let Some(sel) = continues {
            let parent = parse_id(require(&p, "parent")?)?;
            let sel = parse_id(sel)?;
            (
                CandidateBasis::Continuation,
                Some(parent),
                vec![Ref {
                    type_: RefType::Cause,
                    target: sel,
                }],
            )
        } else if let Some(ids) = derives {
            let refs = ids
                .iter()
                .map(|s| {
                    parse_id(s).map(|t| Ref {
                        type_: RefType::Cause,
                        target: t,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            (CandidateBasis::Derivation, None, refs)
        } else if let Some(target_hex) = upgrades {
            // Binding upgrade: a Derivation over the target with the SAME tree.
            // The CLI refuses to build an upgrade whose tree differs from its
            // target's (SPEC §2 recording discipline).
            let target = parse_id(target_hex)?;
            let target_data = find_candidate(writer.records(), target).ok_or_else(|| {
                format!("--upgrades target {target_hex:?} is not a Candidate in this log")
            })?;
            // A Derivation's Cause target must be an accepted, live candidate;
            // upgrading onto a rejected or retracted one only mints a record
            // the verifier will reject, so refuse before the write.
            if !state.accepted_records.contains(&target) {
                return Err(format!(
                    "--upgrades target {target_hex:?} is not an accepted Candidate"
                ));
            }
            if state.retracted_records.contains(&target) {
                return Err(format!(
                    "--upgrades target {target_hex:?} is retracted; upgrade a live candidate"
                ));
            }
            if target_data.source.git.tree != tree {
                return Err(format!(
                    "refusing upgrade: --git-tree {tree:?} differs from the target candidate's tree {:?}",
                    target_data.source.git.tree
                ));
            }
            (
                CandidateBasis::Derivation,
                None,
                vec![Ref {
                    type_: RefType::Cause,
                    target,
                }],
            )
        } else {
            (CandidateBasis::Root, None, Vec::new())
        };

        // A manifest binding when --manifest is given; reported otherwise.
        let (manifest_hash_val, binding) = match p.singles.get("manifest") {
            Some(path) => (Some(manifest_binding(path)?), BindingMode::Manifest),
            None => (None, BindingMode::Reported),
        };

        let data = checked_encode(&CandidateData {
            source: SourceBinding {
                git: GitSource { algo, tree, commit },
                manifest_hash: manifest_hash_val,
                binding,
            },
            basis,
            parent,
            note,
        })?;

        let proposal = Proposal {
            space: rules.space,
            thread: rules.space, // single-thread CLI: thread == space id
            author,
            kind: Kind::Candidate,
            schema: schema_id(SCHEMA_CANDIDATE),
            data,
            refs,
        };
        commit_and_print(writer, &rules, state, proposal, p.bools.contains("json"))
    }

    // --- eval add ----------------------------------------------------------

    pub fn eval(rest: &[String]) -> Result<ExitCode, String> {
        let (sub, rest) = rest
            .split_first()
            .ok_or_else(|| "eval needs a subcommand (add)".to_string())?;
        if sub != "add" {
            return Err(format!("unknown eval subcommand {sub:?} (expected add)"));
        }
        let p = parse(
            rest,
            &[
                "log",
                "rules",
                "author",
                "candidate",
                "criterion",
                "procedure",
                "score",
                "scale",
            ],
            &["uses"],
            &["json", "passed", "failed"],
        )?;
        let rules = load_rules(&p)?;
        let (writer, state) = open(&p, &rules)?;
        let author = author(&rules, &p)?;

        let candidate = parse_id(require(&p, "candidate")?)?;
        let criterion = require(&p, "criterion")?.to_string();
        let procedure = p.singles.get("procedure").cloned();

        let outcome = match (
            p.bools.contains("passed"),
            p.bools.contains("failed"),
            p.singles.get("score"),
        ) {
            (true, false, None) => EvaluationOutcome::Passed,
            (false, true, None) => EvaluationOutcome::Failed,
            (false, false, Some(score)) => {
                let value = score
                    .parse::<i64>()
                    .map_err(|_| "invalid --score".to_string())?;
                let scale = require(&p, "scale")?
                    .parse::<u8>()
                    .map_err(|_| "invalid --scale".to_string())?;
                EvaluationOutcome::Scored(ScoredValue { value, scale })
            }
            _ => return Err("exactly one of --passed, --failed, or --score is required".into()),
        };

        // The evaluation must Use its candidate, plus any extra --uses refs.
        let mut refs = vec![Ref {
            type_: RefType::Use,
            target: candidate,
        }];
        if let Some(extra) = p.multis.get("uses") {
            for s in extra {
                refs.push(Ref {
                    type_: RefType::Use,
                    target: parse_id(s)?,
                });
            }
        }

        let data = checked_encode(&EvaluationData {
            candidate,
            criterion,
            procedure,
            outcome,
        })?;

        let proposal = Proposal {
            space: rules.space,
            thread: rules.space,
            author,
            kind: Kind::Evaluation,
            schema: schema_id(SCHEMA_EVALUATION),
            data,
            refs,
        };
        commit_and_print(writer, &rules, state, proposal, p.bools.contains("json"))
    }

    // --- retract -----------------------------------------------------------

    /// Retract a committed record: assert its content is wrong. The target
    /// stays in the log; on acceptance its id enters the retracted set, its
    /// epistemic dependents become tainted, and the receipt reports Tainted
    /// from then on - permanently. Ownership is the verifier's (SPEC 2): the
    /// retraction is accepted only when `--author` is the target's author or
    /// an admin retraction actor (`rules init --admin`); an Executor may
    /// never author one; a Verdict or Retraction cannot be retracted. A
    /// rejected retraction is still durably committed, exit 65, with the
    /// verifier's reason.
    pub fn retract(rest: &[String]) -> Result<ExitCode, String> {
        let p = parse(
            rest,
            &["log", "rules", "author", "target", "reason"],
            &[],
            &["json"],
        )?;
        let rules = load_rules(&p)?;
        let (writer, state) = open(&p, &rules)?;
        let author = author(&rules, &p)?;

        let target = parse_id(require(&p, "target")?)?;
        let reason = require(&p, "reason")?.to_string();

        // The verifier requires exactly one Cause ref naming the target.
        let refs = vec![Ref {
            type_: RefType::Cause,
            target,
        }];
        let data = checked_encode(&RetractionData {
            target_id: target,
            reason,
        })?;

        let proposal = Proposal {
            space: rules.space,
            thread: rules.space,
            author,
            kind: Kind::Retraction,
            schema: schema_id(SCHEMA_RETRACTION),
            data,
            refs,
        };
        commit_and_print(writer, &rules, state, proposal, p.bools.contains("json"))
    }

    // --- select ------------------------------------------------------------

    pub fn select(rest: &[String]) -> Result<ExitCode, String> {
        let p = parse(
            rest,
            &[
                "log",
                "rules",
                "author",
                "objective",
                "rationale",
                "replaces",
            ],
            &["consider", "choose", "uses-eval"],
            &["json", "none"],
        )?;
        let rules = load_rules(&p)?;
        let (writer, state) = open(&p, &rules)?;
        let author = author(&rules, &p)?;

        let objective = require(&p, "objective")?.to_string();
        let considered = p
            .multis
            .get("consider")
            .ok_or_else(|| "--consider requires at least one candidate id".to_string())?
            .iter()
            .map(|s| parse_id(s))
            .collect::<Result<Vec<_>, _>>()?;
        let rationale = p.singles.get("rationale").cloned();

        let none = p.bools.contains("none");
        let choose = p.multis.get("choose");
        if none == choose.is_some() {
            return Err("exactly one of --choose or --none is required".into());
        }

        let mut refs = Vec::new();
        let outcome = if none {
            SelectionOutcome::None
        } else {
            let winners = choose
                .unwrap()
                .iter()
                .map(|s| parse_id(s))
                .collect::<Result<Vec<_>, _>>()?;
            for w in &winners {
                refs.push(Ref {
                    type_: RefType::Require,
                    target: *w,
                });
            }
            // Evaluations are required with --choose.
            let evals = p.multis.get("uses-eval").ok_or_else(|| {
                "--choose requires --uses-eval with at least one evaluation".to_string()
            })?;
            for s in evals {
                refs.push(Ref {
                    type_: RefType::Use,
                    target: parse_id(s)?,
                });
            }
            SelectionOutcome::Selected {
                candidates: winners,
            }
        };

        // Reaffirmation: --replaces adds a Replace ref to a prior Selection.
        if let Some(sel) = p.singles.get("replaces") {
            refs.push(Ref {
                type_: RefType::Replace,
                target: parse_id(sel)?,
            });
        }

        let data = checked_encode(&SelectionData {
            objective,
            considered,
            outcome,
            rationale,
        })?;

        let proposal = Proposal {
            space: rules.space,
            thread: rules.space,
            author,
            kind: Kind::Selection,
            schema: schema_id(SCHEMA_SELECTION),
            data,
            refs,
        };
        commit_and_print(writer, &rules, state, proposal, p.bools.contains("json"))
    }

    // --- lineage -----------------------------------------------------------

    #[derive(serde::Serialize)]
    struct LineageReport {
        id: String,
        kind: String,
        basis: Option<String>,
        parent: Option<String>,
        note: Option<String>,
        tainted: bool,
        standing: String,
        ancestors: Vec<String>,
        children: Vec<String>,
        siblings: Vec<String>,
        considered_by: Vec<String>,
        selected_by: Vec<String>,
    }

    pub fn lineage(rest: &[String]) -> Result<ExitCode, String> {
        let p = parse(rest, &["log", "rules"], &[], &["json"])?;
        let rules = load_rules(&p)?;
        let dir = require(&p, "log")?;
        let target_hex = p
            .positionals
            .first()
            .ok_or_else(|| "lineage requires a record id".to_string())?;
        let target = parse_id(target_hex)?;

        let writer =
            LogWriter::open(std::path::Path::new(dir), &rules).map_err(|e| format!("{e:?}"))?;
        let records = writer.records();
        let verdict = verify_log(records, &rules, None);
        if verdict.result != VerdictResult::Accept {
            return Err("the log does not verify under these rules".into());
        }

        let rec = records
            .iter()
            .find(|r| r.id == target)
            .ok_or_else(|| format!("record {target_hex:?} not found in the log"))?;

        // Candidate lineage facts (if the target is a candidate).
        let cand = decode::<CandidateData>(&rec.data)
            .ok()
            .filter(|_| rec.kind == Kind::Candidate);

        // Ancestors: walk the parent chain (continuations) upward.
        let mut ancestors = Vec::new();
        {
            let mut cur = cand.as_ref().and_then(|c| c.parent);
            while let Some(pid) = cur {
                ancestors.push(hex_encode(&pid));
                cur = find_candidate(records, pid).and_then(|c| c.parent);
            }
        }

        // Children: candidates whose parent is the target, or whose Cause
        // targets include it (derivations). Siblings: candidates sharing the
        // target's parent.
        let mut children = Vec::new();
        let mut siblings = Vec::new();
        let target_parent = cand.as_ref().and_then(|c| c.parent);
        for r in records {
            if r.kind != Kind::Candidate {
                continue;
            }
            let Ok(cd) = decode::<CandidateData>(&r.data) else {
                continue;
            };
            let is_child = cd.parent == Some(target)
                || r.refs
                    .iter()
                    .any(|rf| rf.type_ == RefType::Cause && rf.target == target);
            if is_child && r.id != target {
                children.push(hex_encode(&r.id));
            }
            if r.id != target && target_parent.is_some() && cd.parent == target_parent {
                siblings.push(hex_encode(&r.id));
            }
        }

        // Selections that considered or selected the target.
        let mut considered_by = Vec::new();
        let mut selected_by = Vec::new();
        for r in records {
            if r.kind != Kind::Selection {
                continue;
            }
            let Ok(sd) = decode::<SelectionData>(&r.data) else {
                continue;
            };
            if sd.considered.contains(&target) {
                considered_by.push(hex_encode(&r.id));
            }
            if let SelectionOutcome::Selected { candidates } = &sd.outcome {
                if candidates.contains(&target) {
                    selected_by.push(hex_encode(&r.id));
                }
            }
        }

        let standing = if rec.kind == Kind::Candidate {
            if verdict.standing.compromised.contains(&target) {
                "compromised"
            } else {
                "sound"
            }
        } else if rec.kind == Kind::Selection {
            if verdict.standing.unsound.contains(&target) {
                "unsound"
            } else {
                "sound"
            }
        } else {
            "n/a"
        }
        .to_string();

        let report = LineageReport {
            id: hex_encode(&target),
            kind: format!("{:?}", rec.kind),
            basis: cand.as_ref().map(|c| format!("{:?}", c.basis)),
            parent: cand.as_ref().and_then(|c| c.parent).map(|p| hex_encode(&p)),
            note: cand.as_ref().and_then(|c| c.note.clone()),
            tainted: verdict.tainted_records.contains(&target),
            standing,
            ancestors,
            children,
            siblings,
            considered_by,
            selected_by,
        };

        if p.bools.contains("json") {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| format!("{e}"))?
            );
        } else {
            println!("id:          {}", report.id);
            println!("kind:        {}", report.kind);
            if let Some(b) = &report.basis {
                println!("basis:       {b}");
            }
            if let Some(pt) = &report.parent {
                println!("parent:      {pt}");
            }
            if let Some(n) = &report.note {
                println!("note:        {n}");
            }
            println!("tainted:     {}", report.tainted);
            println!("standing:    {}", report.standing);
            let list = |label: &str, v: &[String]| {
                if !v.is_empty() {
                    println!("{label} ({}):", v.len());
                    for x in v {
                        println!("  {x}");
                    }
                }
            };
            list("ancestors", &report.ancestors);
            list("children", &report.children);
            list("siblings", &report.siblings);
            list("considered-by", &report.considered_by);
            list("selected-by", &report.selected_by);
        }
        Ok(ExitCode::SUCCESS)
    }
}
