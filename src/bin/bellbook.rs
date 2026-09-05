//! `bellbook` - accountability-ledger CLI.
//!
//! `validate <receipt>` verifies a receipt offline (feature-independent). The
//! evolution subcommands (`candidate`, `eval`, `select`, `retract`,
//! `lineage`, `query`) are thin wrappers over the crate that operate on a
//! persistent log and therefore need the `persist` feature; JSON in/out, and
//! every mutating command prints the committed record id.
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
                           [--require-profile <id>] ...
    bellbook request add   --log <dir> --rules <file> --author <id>
                           --objective <s> [--json]
    bellbook requirement add --log <dir> --rules <file> --author <id>
                           --request <id> --key <s> --description <s>
                           [--optional] [--expected-evidence <s>]
                           [--provenance user-authored|derived] [--json]
    bellbook candidate add --log <dir> --rules <file> --author <id>
                           --git-tree <oid> [--git-commit <oid>] [--algo sha1|sha256]
                           [--manifest <path-to-tree>]
                           [--artifact <scheme>:<digest>[:<name>] ...]
                           [--continues <selection-id> --parent <candidate-id>
                            | --derives-from <id> ...
                            | --upgrades <candidate-id>]
                           [--note <s>] [--json]
    bellbook eval add      --log <dir> --rules <file> --author <id>
                           --candidate <id> --criterion <s>
                           (--passed | --failed | --score <value> --scale <n>
                            | --blocked | --insufficient | --stale | --not-run)
                           [--procedure <s>] [--uses <id> ...] [--json]
                           [--evaluator <id> --basis recomputed|declared
                            [--evaluator-version <s>] [--procedure-hash <hex>]
                            [--input-hash <hex>] [--requirement <id> ...]
                            [--artifact <scheme>:<digest>[:<name>] ...]]
    bellbook select        --log <dir> --rules <file> --author <id>
                           --objective <s> --consider <id> ...
                           (--choose <id> ... --uses-eval <id> ... | --none)
                           [--replaces <selection-id>] [--rationale <s>] [--json]
    bellbook retract       --log <dir> --rules <file> --author <id>
                           --target <record-id> --reason <text> [--json]
    bellbook lineage       --log <dir> --rules <file> <id> [--json]
    bellbook query <name> [<id>|<objective>]
                           (--log <dir> --rules <file> | --receipt <file>) [--json]
    bellbook rules init    --author <id>:<role> ... [--admin <id>] ... [--reaffirmer <id>] ...
                           [--max-context <n>] [--out <file>]
    bellbook export        --log <dir> --rules <file> [--out <file>]
                           [--profile <id> ...]

COMMANDS:
    validate    Verify a receipt offline: ids (RFC 8785 canonical form),
                gap-free logical time, verdict re-derivation, signatures,
                evidence derivation, taint, and the standing section.
                Every profile the receipt declares is evaluated and
                reported alongside the verdict, never trusted;
                --require-profile evaluates a named profile (bellbook-core-v1
                or delivery-receipt-v1) the receipt did not declare. A receipt
                that validates but does not conform to a declared or
                required profile exits 3, as does a declaration whose
                version or hash is not the profile this binary evaluated.
    request     Record a Request (what a person asked for). Author must be
                a user role; requirements bind to it.
    requirement Record a Requirement under a request: an addressable
                statement of what it requires, with a key unique among the
                request's live requirements. --provenance defaults from the
                author's role (user -> user-authored, provider or system ->
                derived); the verifier binds the two.
    candidate   Record a Candidate (a proposed source state). --artifact
                binds artifact identities (registered schemes: git-tree-sha1,
                git-tree-sha256, manifest-v1, git-archive-tar-v1,
                oci-image-manifest, sha256-bytes).
    eval        Record an Evaluation of a candidate. With --evaluator and
                --basis it records the extended shape (bellbook.evaluation.v2):
                who decided with what procedure over what input, the
                artifacts judged (--artifact), the requirements it speaks to
                (--requirement), and the fail-closed outcomes; only --passed
                passes. Without them it records the v1 shape.
    select      Record a Selection over candidates (or a reaffirmation).
    retract     Assert a committed record's content is wrong. The target
                stays in the log; the receipt reports Tainted from then on.
                Accepted only from the target's author or an admin actor.
    lineage     Show a candidate's descent, siblings, taint, and standing.
    query       Run one named read-side query (RFC-0002) over a verified
                log or a portable receipt: descent <id>, descendants <id>,
                siblings <id>, frontier, standing <id>, evidence <id>,
                selected <objective>. Deterministic and read-only; the
                --json output is the shared shape every surface emits.
    rules init  Generate a starter verifier-rules file. Roles are one of
                user|provider|system|executor|verifier. --admin allows an
                actor to retract records it did not author; --reaffirmer
                restricts reaffirming selections to the listed actors.
    export      Bundle a log directory into a portable receipt (the input
                `bellbook validate` verifies). --profile declares a profile
                the receipt claims; every validator re-checks the claim.

EXIT CODES:
    0 clean/success   1 invalid   2 tainted   3 profile not met   64 usage
    65 command failed   66 unreadable input   70 internal error\
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
        "request" | "requirement" | "candidate" | "eval" | "select" | "retract" | "lineage"
        | "export" | "query" => cmd_evolution(command, &rest),
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

    // Baseline evidence thresholds (RFC-0003 clause B3) are on by default so
    // a generated rule set conforms to bellbook-core-v1 out of the box.
    let mut rules = VerifierRules::new(default_space(), max_context).with_baseline_thresholds();
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
    let mut profiles: Vec<&str> = Vec::new();
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--require-profile" => {
                let Some(v) = it.next() else {
                    eprintln!("--require-profile requires a profile id\n\n{USAGE}");
                    return ExitCode::from(64);
                };
                if v.is_empty() || v.starts_with('-') {
                    eprintln!("--require-profile requires a profile id (found {v:?})");
                    return ExitCode::from(64);
                }
                profiles.push(v.as_str());
            }
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
    let report = validate_with_profiles(&bytes, &limits, &profiles);

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

    // Verdict first: an Invalid receipt is 1 whatever was requested.
    // A receipt that validates but misses a declared or required profile is
    // 3 - a distinct answer from "valid" so a caller cannot mistake one for
    // the other. Unknown profile ids count as not met (a guarantee this
    // validator cannot evaluate), and so does a declaration naming a
    // version or hash other than the profile evaluated here: the claim the
    // receipt made is not the one that was checked.
    let profile_missed = report.profiles.iter().any(|p| !p.met());
    match report.status {
        ValidationStatus::Invalid => ExitCode::from(1),
        _ if profile_missed => ExitCode::from(3),
        ValidationStatus::Clean => ExitCode::SUCCESS,
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
        "request" => persist_cmds::request(rest),
        "requirement" => persist_cmds::requirement(rest),
        "candidate" => persist_cmds::candidate(rest),
        "eval" => persist_cmds::eval(rest),
        "select" => persist_cmds::select(rest),
        "retract" => persist_cmds::retract(rest),
        "lineage" => persist_cmds::lineage(rest),
        "export" => persist_cmds::export(rest),
        "query" => persist_cmds::query(rest),
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

    fn parse_hash(flag: &str, hex: &str) -> Result<Hash256, String> {
        hex_decode(hex).ok_or_else(|| format!("invalid --{flag} {hex:?} (expected 64 hex chars)"))
    }

    /// `--artifact <scheme>:<digest>[:<name>]`, repeatable. Each reference
    /// is checked against the artifact rule before anything is written
    /// (scheme token, lowercase-hex digest of the scheme's length), and the
    /// list is sorted and deduplicated into the canonical order the verifier
    /// requires, so a well-formed command never mints an
    /// `ArtifactRefInvalid` record. `None` when no flag was given.
    fn parse_artifacts(p: &Parsed) -> Result<Option<Vec<ArtifactRef>>, String> {
        let Some(specs) = p.multis.get("artifact") else {
            return Ok(None);
        };
        let mut refs = Vec::with_capacity(specs.len());
        for spec in specs {
            let mut parts = spec.splitn(3, ':');
            let scheme = parts.next().unwrap_or_default().to_string();
            let digest = parts
                .next()
                .ok_or_else(|| {
                    format!("invalid --artifact {spec:?} (expected <scheme>:<digest>[:<name>])")
                })?
                .to_string();
            let name = parts.next().map(str::to_string);
            let a = ArtifactRef {
                scheme,
                digest,
                name,
            };
            if !artifact_ref_well_formed(&a) {
                return Err(format!(
                    "invalid --artifact {spec:?}: scheme must match [a-z0-9][a-z0-9.-]* and the digest must be lowercase hex of the scheme's length"
                ));
            }
            refs.push(a);
        }
        refs.sort();
        refs.dedup();
        Ok(Some(refs))
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
    /// `--profile <id>` (repeatable) declares a profile the receipt claims;
    /// the declaration is not evaluated here - every validator re-checks it
    /// - so the export succeeds even if the claim turns out false.
    pub fn export(rest: &[String]) -> Result<ExitCode, String> {
        let p = parse(rest, &["log", "rules", "out"], &["profile"], &[])?;
        let rules = load_rules(&p)?;
        let (writer, _state) = open(&p, &rules)?;
        let declared: Vec<&str> = p
            .multis
            .get("profile")
            .map(|ids| ids.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let bytes = Receipt::new(writer.records(), &rules)
            .with_declared_profiles(&declared)?
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

    // --- request add -------------------------------------------------------

    /// Record a Request: what a person asked for. Single-thread CLI, so the
    /// request's scope is the space and it has no parent request. The
    /// verifier admits only a user-role author.
    pub fn request(rest: &[String]) -> Result<ExitCode, String> {
        let (sub, rest) = rest
            .split_first()
            .ok_or_else(|| "request needs a subcommand (add)".to_string())?;
        if sub != "add" {
            return Err(format!("unknown request subcommand {sub:?} (expected add)"));
        }
        let p = parse(
            rest,
            &["log", "rules", "author", "objective"],
            &[],
            &["json"],
        )?;
        let rules = load_rules(&p)?;
        let (writer, state) = open(&p, &rules)?;
        let author = author(&rules, &p)?;
        let objective = require(&p, "objective")?.to_string();
        let data = checked_encode(&RequestData {
            objective,
            scope: rules.space,
            attachments: Vec::new(),
            parent_request_id: None,
        })?;
        let proposal = Proposal {
            space: rules.space,
            thread: rules.space,
            author,
            kind: Kind::Request,
            schema: schema_id(SCHEMA_REQUEST),
            data,
            refs: Vec::new(),
        };
        commit_and_print(writer, &rules, state, proposal, p.bools.contains("json"))
    }

    // --- requirement add ---------------------------------------------------

    /// Record a Requirement under a request (spec 0.4). Exactly one `Cause`
    /// to the request; the key must be unique among the request's accepted,
    /// unretracted requirements, and provenance is bound to the author's
    /// role by the verifier - the CLI derives the default from the role and
    /// refuses a stated provenance the role cannot carry, so a mismatch is a
    /// clean error rather than a durable rejected record.
    pub fn requirement(rest: &[String]) -> Result<ExitCode, String> {
        let (sub, rest) = rest
            .split_first()
            .ok_or_else(|| "requirement needs a subcommand (add)".to_string())?;
        if sub != "add" {
            return Err(format!(
                "unknown requirement subcommand {sub:?} (expected add)"
            ));
        }
        let p = parse(
            rest,
            &[
                "log",
                "rules",
                "author",
                "request",
                "key",
                "description",
                "expected-evidence",
                "provenance",
            ],
            &[],
            &["json", "optional"],
        )?;
        let rules = load_rules(&p)?;
        let (writer, state) = open(&p, &rules)?;
        let author = author(&rules, &p)?;

        let request = parse_id(require(&p, "request")?)?;
        if !state.accepted_records.contains(&request)
            || !writer
                .records()
                .iter()
                .any(|r| r.id == request && r.kind == Kind::Request)
        {
            return Err(format!(
                "--request {} is not an accepted Request in this log",
                hex_encode(&request)
            ));
        }
        let key = require(&p, "key")?.to_string();
        let description = require(&p, "description")?.to_string();
        if key.is_empty() || description.is_empty() {
            return Err("--key and --description must be non-empty".into());
        }
        let role_default = match author.type_ {
            AuthorType::User => Provenance::UserAuthored,
            AuthorType::Provider | AuthorType::System => Provenance::Derived,
            other => {
                return Err(format!(
                    "author {:?} has role {other:?}, which cannot author a Requirement",
                    author.id
                ))
            }
        };
        let provenance = match p.singles.get("provenance").map(String::as_str) {
            None => role_default,
            Some("user-authored") => Provenance::UserAuthored,
            Some("derived") => Provenance::Derived,
            Some(other) => {
                return Err(format!(
                    "invalid --provenance {other:?} (expected user-authored or derived)"
                ))
            }
        };
        if provenance != role_default {
            return Err(format!(
                "--provenance {} cannot be authored by {:?} (role {:?}): provenance is bound to the author's role",
                match provenance {
                    Provenance::UserAuthored => "user-authored",
                    Provenance::Derived => "derived",
                },
                author.id,
                author.type_
            ));
        }

        let data = checked_encode(&RequirementData {
            key,
            description,
            required: !p.bools.contains("optional"),
            expected_evidence: p.singles.get("expected-evidence").cloned(),
            provenance,
        })?;
        let proposal = Proposal {
            space: rules.space,
            thread: rules.space,
            author,
            kind: Kind::Requirement,
            schema: schema_id(SCHEMA_REQUIREMENT),
            data,
            refs: vec![Ref {
                type_: RefType::Cause,
                target: request,
            }],
        };
        commit_and_print(writer, &rules, state, proposal, p.bools.contains("json"))
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
            &["derives-from", "artifact"],
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
            artifacts: parse_artifacts(&p)?,
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
                "evaluator",
                "evaluator-version",
                "procedure-hash",
                "input-hash",
                "basis",
            ],
            &["uses", "requirement", "artifact"],
            &[
                "json",
                "passed",
                "failed",
                "blocked",
                "insufficient",
                "stale",
                "not-run",
            ],
        )?;
        let rules = load_rules(&p)?;
        let (writer, state) = open(&p, &rules)?;
        let author = author(&rules, &p)?;

        let candidate = parse_id(require(&p, "candidate")?)?;
        let criterion = require(&p, "criterion")?.to_string();
        let procedure = p.singles.get("procedure").cloned();

        // Exactly one outcome. The four fail-closed outcomes exist only in
        // the extended shape (spec 0.4); v1 knows passed, failed, scored.
        let unit_outcomes: Vec<&str> = [
            "passed",
            "failed",
            "blocked",
            "insufficient",
            "stale",
            "not-run",
        ]
        .into_iter()
        .filter(|f| p.bools.contains(*f))
        .collect();
        let scored = match p.singles.get("score") {
            Some(score) => {
                let value = score
                    .parse::<i64>()
                    .map_err(|_| "invalid --score".to_string())?;
                let scale = require(&p, "scale")?
                    .parse::<u8>()
                    .map_err(|_| "invalid --scale".to_string())?;
                Some(ScoredValue { value, scale })
            }
            None => None,
        };
        if unit_outcomes.len() + usize::from(scored.is_some()) != 1 {
            return Err("exactly one outcome is required: --passed, --failed, --score <value> --scale <n>, --blocked, --insufficient, --stale, or --not-run".into());
        }
        let outcome_v2 = match (unit_outcomes.first().copied(), scored) {
            (_, Some(s)) => EvaluationOutcomeV2::Scored(s),
            (Some("passed"), None) => EvaluationOutcomeV2::Passed,
            (Some("failed"), None) => EvaluationOutcomeV2::Failed,
            (Some("blocked"), None) => EvaluationOutcomeV2::Blocked,
            (Some("insufficient"), None) => EvaluationOutcomeV2::Insufficient,
            (Some("stale"), None) => EvaluationOutcomeV2::Stale,
            (Some("not-run"), None) => EvaluationOutcomeV2::NotRun,
            _ => unreachable!("one outcome flag was checked above"),
        };

        // The extended shape is chosen by its binding flags: --evaluator and
        // --basis together, since basis is declared and never inferred. Any
        // other 0.4-only flag or outcome needs them, and a mismatch is a
        // clean error rather than a rejected record.
        let extended_flags: Vec<&str> = [
            "evaluator",
            "evaluator-version",
            "procedure-hash",
            "input-hash",
            "basis",
        ]
        .into_iter()
        .filter(|f| p.singles.contains_key(*f))
        .chain(
            ["requirement", "artifact"]
                .into_iter()
                .filter(|f| p.multis.contains_key(*f)),
        )
        .chain(
            ["blocked", "insufficient", "stale", "not-run"]
                .into_iter()
                .filter(|f| p.bools.contains(*f)),
        )
        .collect();
        let extended = !extended_flags.is_empty();
        if extended && !(p.singles.contains_key("evaluator") && p.singles.contains_key("basis")) {
            return Err(format!(
                "the extended evaluation (--{}) requires both --evaluator <id> and --basis recomputed|declared",
                extended_flags.join(", --")
            ));
        }

        // The evaluation must Use its candidate, then each requirement it
        // speaks to (mirrored in the payload), then any extra --uses refs.
        let mut refs = vec![Ref {
            type_: RefType::Use,
            target: candidate,
        }];
        let mut requirements: Vec<RecordId> = p
            .multis
            .get("requirement")
            .map(|ids| ids.iter().map(|s| parse_id(s)).collect::<Result<_, _>>())
            .transpose()?
            .unwrap_or_default();
        requirements.sort();
        requirements.dedup();
        for rid in &requirements {
            if !writer
                .records()
                .iter()
                .any(|r| r.id == *rid && r.kind == Kind::Requirement)
                || !state.accepted_records.contains(rid)
            {
                return Err(format!(
                    "--requirement {} is not an accepted Requirement in this log",
                    hex_encode(rid)
                ));
            }
            refs.push(Ref {
                type_: RefType::Use,
                target: *rid,
            });
        }
        if let Some(extra) = p.multis.get("uses") {
            for s in extra {
                refs.push(Ref {
                    type_: RefType::Use,
                    target: parse_id(s)?,
                });
            }
        }

        let (schema, data) = if extended {
            let evaluator_id = require(&p, "evaluator")?.to_string();
            if evaluator_id.is_empty() {
                return Err("--evaluator must be non-empty".into());
            }
            let basis = match require(&p, "basis")? {
                "recomputed" => Basis::Recomputed,
                "declared" => Basis::Declared,
                other => {
                    return Err(format!(
                        "invalid --basis {other:?} (expected recomputed or declared)"
                    ))
                }
            };
            let procedure_hash = p
                .singles
                .get("procedure-hash")
                .map(|h| parse_hash("procedure-hash", h))
                .transpose()?;
            let input_hash = p
                .singles
                .get("input-hash")
                .map(|h| parse_hash("input-hash", h))
                .transpose()?;
            let data = checked_encode(&EvaluationDataV2 {
                candidate,
                criterion,
                procedure,
                outcome: outcome_v2,
                evaluator: DeciderBinding {
                    id: evaluator_id,
                    version: p.singles.get("evaluator-version").cloned(),
                    procedure_hash,
                    input_hash,
                },
                basis,
                evidence: parse_artifacts(&p)?.unwrap_or_default(),
                requirements,
            })?;
            (SCHEMA_EVALUATION_V2, data)
        } else {
            let outcome = match outcome_v2 {
                EvaluationOutcomeV2::Passed => EvaluationOutcome::Passed,
                EvaluationOutcomeV2::Failed => EvaluationOutcome::Failed,
                EvaluationOutcomeV2::Scored(s) => EvaluationOutcome::Scored(s),
                _ => unreachable!("fail-closed outcomes select the extended shape"),
            };
            let data = checked_encode(&EvaluationData {
                candidate,
                criterion,
                procedure,
                outcome,
            })?;
            (SCHEMA_EVALUATION, data)
        };

        let proposal = Proposal {
            space: rules.space,
            thread: rules.space,
            author,
            kind: Kind::Evaluation,
            schema: schema_id(schema),
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

    // --- query -------------------------------------------------------------

    /// One node as a single human-readable fragment: id plus the
    /// annotations a reader needs to judge it (kind, standing, taint,
    /// retraction).
    fn node_str(n: &Node) -> String {
        let mut s = format!("{} [{} {}", n.id, n.kind, n.standing);
        if n.tainted {
            s.push_str(", tainted");
        }
        if n.retracted {
            s.push_str(", retracted");
        }
        // Bindings (spec 0.4), where present: what the record was bound to.
        if !n.artifacts.is_empty() {
            let list: Vec<String> = n
                .artifacts
                .iter()
                .map(|a| format!("{}:{}", a.scheme, a.digest))
                .collect();
            s.push_str(&format!(", artifacts {}", list.join(" ")));
        }
        if !n.requirements.is_empty() {
            s.push_str(&format!(", requirements {}", n.requirements.join(" ")));
        }
        s.push(']');
        s
    }

    fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
        println!(
            "{}",
            serde_json::to_string_pretty(value).map_err(|e| format!("{e}"))?
        );
        Ok(())
    }

    fn evidence_lines(indent: &str, entries: &[EvidenceEntry]) {
        for e in entries {
            println!(
                "{indent}{} -> {}  {}",
                e.criterion,
                e.outcome,
                node_str(&e.node)
            );
        }
    }

    /// `query <name> [arg]` runs one named read-side query (RFC-0002) over
    /// a verified log (`--log` with `--rules`) or a portable receipt
    /// (`--receipt`, rules embedded), printing the shared JSON shape with
    /// `--json` or a human rendering. Queries never answer over unverified
    /// history: an invalid log or receipt is an error, not data.
    pub fn query(rest: &[String]) -> Result<ExitCode, String> {
        let (name, rest) = rest.split_first().ok_or_else(|| {
            "query needs a name \
             (descent|descendants|siblings|frontier|standing|evidence|selected)"
                .to_string()
        })?;
        let p = parse(rest, &["log", "rules", "receipt"], &[], &["json"])?;

        let has_log = p.singles.contains_key("log");
        let has_receipt = p.singles.contains_key("receipt");
        if has_log == has_receipt {
            return Err(
                "query requires exactly one input: --log with --rules, or --receipt".to_string(),
            );
        }
        // A receipt embeds its rules; a separate --rules with --receipt is
        // stated intent that cannot be honored, so refuse rather than drop it.
        if has_receipt && p.singles.contains_key("rules") {
            return Err("--rules is not valid with --receipt (a receipt embeds its rules)".into());
        }
        if p.positionals.len() > 1 {
            return Err(format!(
                "query {name} takes at most one argument, got {:?}",
                p.positionals
            ));
        }

        let (records, rules): (Vec<Record>, VerifierRules) = if has_log {
            let rules = load_rules(&p)?;
            let dir = require(&p, "log")?;
            let writer =
                LogWriter::open(std::path::Path::new(dir), &rules).map_err(|e| format!("{e:?}"))?;
            (writer.records().to_vec(), rules)
        } else {
            let path = require(&p, "receipt")?;
            let bytes =
                std::fs::read(path).map_err(|e| format!("cannot read receipt {path}: {e}"))?;
            // The full offline validation first, so a structurally broken
            // receipt reports its problem (limits, strict decoding, spec
            // version), not a replay error.
            let report = validate(&bytes);
            if report.status == ValidationStatus::Invalid {
                let why = report
                    .problem
                    .or_else(|| report.reason.map(|r| format!("{r:?}")))
                    .unwrap_or_else(|| "?".to_string());
                return Err(format!("receipt does not validate: {why}"));
            }
            let receipt = Receipt::from_bytes(&bytes)
                .map_err(|e| format!("cannot parse receipt {path}: {e}"))?;
            (receipt.records, receipt.rules)
        };

        let q = Queries::new(&records, &rules).map_err(|e| format!("{e}"))?;
        let json = p.bools.contains("json");
        let arg_id = || -> Result<RecordId, String> {
            let hex = p
                .positionals
                .first()
                .ok_or_else(|| format!("query {name} requires a record id"))?;
            parse_id(hex)
        };

        match name.as_str() {
            "descent" => {
                let r = q.descent(arg_id()?).map_err(|e| format!("{e}"))?;
                if json {
                    print_json(&r)?;
                } else {
                    println!("target: {}", node_str(&r.target));
                    println!("line ({}):", r.line.len());
                    for s in &r.line {
                        println!("  via {:<20} {}", s.via, node_str(&s.node));
                    }
                }
            }
            "descendants" => {
                let r = q.descendants(arg_id()?).map_err(|e| format!("{e}"))?;
                if json {
                    print_json(&r)?;
                } else {
                    println!("target: {}", node_str(&r.target));
                    println!("descendants ({}):", r.descendants.len());
                    for n in &r.descendants {
                        println!("  {}", node_str(n));
                    }
                }
            }
            "siblings" => {
                let r = q.siblings(arg_id()?).map_err(|e| format!("{e}"))?;
                if json {
                    print_json(&r)?;
                } else {
                    println!("target: {}", node_str(&r.target));
                    println!("siblings ({}):", r.siblings.len());
                    for n in &r.siblings {
                        println!("  {}", node_str(n));
                    }
                }
            }
            "frontier" => {
                if !p.positionals.is_empty() {
                    return Err("query frontier takes no argument".to_string());
                }
                let r = q.frontier();
                if json {
                    print_json(&r)?;
                } else {
                    println!("frontier ({}):", r.frontier.len());
                    for e in &r.frontier {
                        println!("  {:<26} {}", e.reason, node_str(&e.node));
                    }
                }
            }
            "standing" => {
                let r = q.standing(arg_id()?).map_err(|e| format!("{e}"))?;
                if json {
                    print_json(&r)?;
                } else {
                    println!("node: {}", node_str(&r.node));
                    println!("restorations ({}):", r.restorations.len());
                    for id in &r.restorations {
                        println!("  {id}");
                    }
                }
            }
            "evidence" => {
                let r = q.evidence(arg_id()?).map_err(|e| format!("{e}"))?;
                if json {
                    print_json(&r)?;
                } else {
                    println!("target: {}", node_str(&r.target));
                    println!("rests_on ({} selections):", r.rests_on.len());
                    for se in &r.rests_on {
                        println!("  selection: {}", node_str(&se.selection));
                        evidence_lines("    ", &se.evidence);
                    }
                }
            }
            "selected" => {
                let objective = p
                    .positionals
                    .first()
                    .ok_or_else(|| "query selected requires an objective string".to_string())?;
                let r = q.selected(objective);
                if json {
                    print_json(&r)?;
                } else {
                    println!("objective: {}", r.objective);
                    println!("selections ({}):", r.selections.len());
                    for s in &r.selections {
                        println!("  selection: {}", node_str(&s.selection));
                        for c in &s.chosen {
                            println!("    chosen: {}", node_str(c));
                        }
                        evidence_lines("    ", &s.evidence);
                    }
                }
            }
            other => {
                return Err(format!(
                    "unknown query {other:?} \
                     (descent|descendants|siblings|frontier|standing|evidence|selected)"
                ))
            }
        }
        Ok(ExitCode::SUCCESS)
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
