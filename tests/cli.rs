//! End-to-end tests for the `bellbook` evolution CLI (`candidate`, `eval`,
//! `select`, `retract`, `lineage`, `query`). Each test drives the real
//! compiled binary against a
//! throwaway log directory, so it exercises the whole path: argument parsing,
//! rules loading, verified open, commit, and JSON output. The binary is
//! single-writer by design, so every command runs as its own process and the
//! log is opened fresh each time - the intended serial recording pattern.

#![cfg(feature = "persist")]

use bellbook::*;
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SPACE: [u8; 32] = [7u8; 32];
// The canonical empty-tree SHA-1 OID; a valid 40-hex tree.
const TREE_A: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
// A distinct, still-valid 40-hex tree OID.
const TREE_B: &str = "1111111111111111111111111111111111111111";

fn rules_json() -> String {
    // "agent" is a Provider - allowed to author Candidate, Evaluation, and
    // Selection - so one identity drives the whole flow.
    let rules = VerifierRules::new(SPACE, 200).with_author_role("agent", AuthorType::Provider);
    serde_json::to_string_pretty(&rules).unwrap()
}

/// A scratch working area: a log dir and a written rules file.
struct Env {
    _dir: tempfile::TempDir,
    log: PathBuf,
    rules: PathBuf,
}

fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log");
    let rules = dir.path().join("rules.json");
    std::fs::write(&rules, rules_json()).unwrap();
    Env {
        _dir: dir,
        log,
        rules,
    }
}

fn bellbook() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bellbook"))
}

/// Run a subcommand and capture its output. `--log`/`--rules` are appended
/// last so any `add` subcommand keyword stays adjacent to its command word.
fn run(env: &Env, args: &[&str]) -> Output {
    let mut cmd = bellbook();
    cmd.args(args);
    cmd.arg("--log").arg(&env.log);
    cmd.arg("--rules").arg(&env.rules);
    cmd.output().unwrap()
}

/// Parse the `id` field from a `--json` commit output.
fn committed_id(out: &Output) -> String {
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["result"], "accept");
    v["id"].as_str().unwrap().to_string()
}

fn add_root(env: &Env, tree: &str) -> String {
    let out = run(
        env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            tree,
            "--json",
        ],
    );
    committed_id(&out)
}

#[test]
fn root_candidate_prints_its_id() {
    let env = setup();
    let id = add_root(&env, TREE_A);
    // A record id is 32 bytes of lowercase hex.
    assert_eq!(id.len(), 64);
    assert!(id
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn upgrade_tree_mismatch_is_refused() {
    let env = setup();
    let root = add_root(&env, TREE_A);
    // Upgrading with a DIFFERENT tree must be refused before it is committed.
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            TREE_B,
            "--upgrades",
            &root,
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing upgrade"),
        "unexpected stderr: {stderr}"
    );
    // The refused upgrade committed nothing: only the root is in the log.
    let out = run(&env, &["lineage", &root, "--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["children"].as_array().unwrap().is_empty());
}

#[test]
fn upgrade_same_tree_is_accepted() {
    let env = setup();
    let root = add_root(&env, TREE_A);
    // Same tree: the guard allows it and it commits as a derivation child.
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            TREE_A,
            "--upgrades",
            &root,
            "--json",
        ],
    );
    let upgraded = committed_id(&out);
    assert_ne!(upgraded, root);

    let out = run(&env, &["lineage", &root, "--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let children: Vec<&str> = v["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert_eq!(children, vec![upgraded.as_str()]);
}

#[test]
fn full_flow_and_lineage_json_round_trips() {
    let env = setup();
    let root = add_root(&env, TREE_A);

    // Evaluate the candidate.
    let out = run(
        &env,
        &[
            "eval",
            "add",
            "--author",
            "agent",
            "--candidate",
            &root,
            "--criterion",
            "unit-tests",
            "--passed",
            "--json",
        ],
    );
    let eval = committed_id(&out);

    // Select it, grounded on the evaluation.
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "ship",
            "--consider",
            &root,
            "--choose",
            &root,
            "--uses-eval",
            &eval,
            "--json",
        ],
    );
    let selection = committed_id(&out);

    // Lineage JSON must round-trip and reflect the recorded relationships.
    let out = run(&env, &["lineage", &root, "--json"]);
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["id"], root);
    assert_eq!(v["kind"], "Candidate");
    assert_eq!(v["basis"], "Root");
    assert_eq!(v["standing"], "sound");
    assert_eq!(v["tainted"], false);
    let considered_by: Vec<&str> = v["considered_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert_eq!(considered_by, vec![selection.as_str()]);
    let selected_by: Vec<&str> = v["selected_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert_eq!(selected_by, vec![selection.as_str()]);

    // The human-readable rendering carries the same facts.
    let out = run(&env, &["lineage", &root]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!("id:          {root}")),
        "text: {text}"
    );
    assert!(text.contains("basis:       Root"), "text: {text}");
    assert!(text.contains("standing:    sound"), "text: {text}");
    assert!(text.contains(&selection), "text: {text}");
}

#[test]
fn none_selection_records() {
    let env = setup();
    let root = add_root(&env, TREE_A);
    // A None selection prunes without choosing; it needs no evaluation.
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "prune",
            "--consider",
            &root,
            "--none",
            "--json",
        ],
    );
    let _ = committed_id(&out);
}

#[test]
fn unknown_author_is_rejected() {
    let env = setup();
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "stranger",
            "--git-tree",
            TREE_A,
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("author_roles"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn out_of_range_score_is_caught_before_commit() {
    let env = setup();
    let root = add_root(&env, TREE_A);
    // scale 13 exceeds the payload's 0..=12 bound. This is statically knowable,
    // so it must be a clean pre-commit error, not a durable rejected record.
    let out = run(
        &env,
        &[
            "eval",
            "add",
            "--author",
            "agent",
            "--candidate",
            &root,
            "--criterion",
            "x",
            "--score",
            "5",
            "--scale",
            "13",
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid payload"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn empty_criterion_is_caught_before_commit() {
    let env = setup();
    let root = add_root(&env, TREE_A);
    let out = run(
        &env,
        &[
            "eval",
            "add",
            "--author",
            "agent",
            "--candidate",
            &root,
            "--criterion",
            "",
            "--passed",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid payload"));
}

#[test]
fn rejected_record_exits_nonzero_with_verdict_json() {
    let env = setup();
    // An invalid (non-hex) tree passes payload decoding but the verifier
    // rejects it (SourceBindingInvalid) at commit: this exercises the reject
    // branch end to end - valid JSON with result "reject" and a nonzero exit.
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            "not-hex",
            "--json",
        ],
    );
    assert!(!out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["result"], "reject");
    assert!(v["reason"].is_string());
    assert_eq!(v["id"].as_str().unwrap().len(), 64);
}

#[test]
fn unknown_flag_is_rejected() {
    let env = setup();
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            TREE_A,
            "--auther",
            "oops",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown flag --auther"));
}

#[test]
fn single_value_flag_does_not_swallow_following_flag() {
    let env = setup();
    let root = add_root(&env, TREE_A);
    // `--procedure` immediately followed by `--passed` must not consume it.
    let out = run(
        &env,
        &[
            "eval",
            "add",
            "--author",
            "agent",
            "--candidate",
            &root,
            "--procedure",
            "--passed",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires a value"));
}

#[test]
fn duplicate_single_flag_is_rejected() {
    let env = setup();
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--author",
            "stranger",
            "--git-tree",
            TREE_A,
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("specified more than once"));
}

#[test]
fn parent_without_continues_is_rejected() {
    let env = setup();
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            TREE_A,
            "--parent",
            "00000000000000000000000000000000000000000000000000000000000000ab",
        ],
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--parent is only valid with --continues")
    );
}

#[test]
fn upgrade_missing_target_is_rejected() {
    let env = setup();
    // A well-formed id that is not in the log at all.
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            TREE_A,
            "--upgrades",
            "00000000000000000000000000000000000000000000000000000000000000ff",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a Candidate in this log"));
}

#[test]
fn rules_init_output_drives_the_other_commands() {
    // `rules init` must produce a rules file the recording commands accept -
    // that is the whole point of removing the hand-authoring step.
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules.json");
    let out = bellbook()
        .args(["rules", "init", "--author", "agent:provider", "--out"])
        .arg(&rules)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // It parses as VerifierRules with the requested binding.
    let parsed: VerifierRules = serde_json::from_str(&std::fs::read_to_string(&rules).unwrap())
        .expect("rules init output must parse as VerifierRules");
    assert_eq!(
        parsed.author_roles.get("agent"),
        Some(&AuthorType::Provider)
    );

    // And it works end to end: record a candidate against it.
    let log = dir.path().join("log");
    let out = bellbook()
        .args([
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            TREE_A,
            "--json",
        ])
        .arg("--log")
        .arg(&log)
        .arg("--rules")
        .arg(&rules)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rules_init_rejects_an_unknown_role() {
    let out = bellbook()
        .args(["rules", "init", "--author", "agent:wizard"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid role"));
}

#[test]
fn export_round_trips_to_a_clean_receipt() {
    let env = setup();
    let root = add_root(&env, TREE_A);
    let out = run(
        &env,
        &[
            "eval",
            "add",
            "--author",
            "agent",
            "--candidate",
            &root,
            "--criterion",
            "unit-tests",
            "--passed",
            "--json",
        ],
    );
    let eval = committed_id(&out);
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "ship",
            "--consider",
            &root,
            "--choose",
            &root,
            "--uses-eval",
            &eval,
            "--json",
        ],
    );
    let _ = committed_id(&out);

    // export the log, then validate the receipt with the same binary: the CLI
    // now closes the record -> receipt -> validate loop without the API.
    let receipt = env._dir.path().join("receipt.json");
    let out = run(&env, &["export", "--out", receipt.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = bellbook().arg("validate").arg(&receipt).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("CLEAN"));
}

#[test]
fn rules_init_to_stdout_parses() {
    // With no --out, the rules JSON goes to stdout and parses as VerifierRules.
    let out = bellbook()
        .args(["rules", "init", "--author", "agent:provider"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let parsed: VerifierRules =
        serde_json::from_slice(&out.stdout).expect("stdout must be a rules object");
    assert_eq!(
        parsed.author_roles.get("agent"),
        Some(&AuthorType::Provider)
    );
}

#[test]
fn rules_init_binds_multiple_authors_and_max_context() {
    let out = bellbook()
        .args([
            "rules",
            "init",
            "--author",
            "agent:provider",
            "--author",
            "human:user",
            "--max-context",
            "42",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let parsed: VerifierRules = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        parsed.author_roles.get("agent"),
        Some(&AuthorType::Provider)
    );
    assert_eq!(parsed.author_roles.get("human"), Some(&AuthorType::User));
    assert_eq!(parsed.max_context_records, 42);
}

#[test]
fn rules_init_needs_an_author() {
    let out = bellbook().args(["rules", "init"]).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least one --author"));
}

#[test]
fn rules_init_binds_admins_and_reaffirmers() {
    let out = bellbook()
        .args([
            "rules",
            "init",
            "--author",
            "agent:provider",
            "--author",
            "human:user",
            "--admin",
            "human",
            "--reaffirmer",
            "human",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: VerifierRules = serde_json::from_slice(&out.stdout).unwrap();
    assert!(parsed.admin_retraction_actors.contains("human"));
    assert!(parsed.reaffirmation_actors.contains("human"));
    // The knobs are opt-in: nothing leaks into the sets besides what was asked.
    assert_eq!(parsed.admin_retraction_actors.len(), 1);
    assert_eq!(parsed.reaffirmation_actors.len(), 1);
}

#[test]
fn rules_init_rejects_an_admin_without_an_author_binding() {
    // An admin with no role binding could never author an accepted record,
    // so the flag would be a silent no-op; it must be refused instead.
    let out = bellbook()
        .args([
            "rules",
            "init",
            "--author",
            "agent:provider",
            "--admin",
            "ghost",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no --author"));

    let out = bellbook()
        .args([
            "rules",
            "init",
            "--author",
            "agent:provider",
            "--reaffirmer",
            "ghost",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no --author"));
}

#[test]
fn rules_init_rejects_bad_max_context() {
    let out = bellbook()
        .args([
            "rules",
            "init",
            "--author",
            "agent:provider",
            "--max-context",
            "lots",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid --max-context"));
}

#[test]
fn export_to_stdout_validates() {
    let env = setup();
    let _root = add_root(&env, TREE_A);
    // No --out: the receipt bytes go to stdout; feed them straight to validate.
    let out = run(&env, &["export"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.stdout.is_empty(), "export wrote nothing to stdout");
    let receipt = env._dir.path().join("stdout-receipt.json");
    std::fs::write(&receipt, &out.stdout).unwrap();
    let out = bellbook().arg("validate").arg(&receipt).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("CLEAN"));
}

#[test]
fn export_of_an_empty_log_succeeds() {
    // A fresh log with nothing committed still exports a (trivially valid)
    // receipt rather than erroring or panicking.
    let env = setup();
    let out = run(&env, &["export"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.stdout.is_empty());
}

#[test]
fn validate_is_feature_independent() {
    // `validate` needs no log; a missing file is an unreadable-input error (66),
    // proving the command dispatches without touching the persist path.
    let out = bellbook()
        .args(["validate", "/nonexistent/receipt.json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
}

// --- retract: the v0.5.0 gate (the broken-benchmark story, CLI alone) ------

/// Rules for the retraction story: two providers plus a human admin who may
/// retract across authors (`admin_retraction_actors`).
fn story_env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log");
    let rules_path = dir.path().join("rules.json");
    let rules = VerifierRules::new(SPACE, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider)
        .with_author_role("human", AuthorType::User)
        .with_admin_retraction_actor("human");
    std::fs::write(&rules_path, serde_json::to_string_pretty(&rules).unwrap()).unwrap();
    Env {
        _dir: dir,
        log,
        rules: rules_path,
    }
}

fn eval_passed(env: &Env, author: &str, candidate: &str, criterion: &str) -> String {
    let out = run(
        env,
        &[
            "eval",
            "add",
            "--author",
            author,
            "--candidate",
            candidate,
            "--criterion",
            criterion,
            "--passed",
            "--json",
        ],
    );
    committed_id(&out)
}

fn validate_receipt(env: &Env, name: &str) -> Output {
    let receipt = env._dir.path().join(name);
    let out = run(env, &["export", "--out", receipt.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    bellbook().arg("validate").arg(&receipt).output().unwrap()
}

#[test]
fn retract_reaffirm_story_runs_from_the_cli_alone() {
    // The v0.5.0 gate, CLI half: build a line, retract the evaluation it
    // rests on, watch standing collapse, reaffirm, watch it restore - with
    // the receipt Tainted permanently from the retraction on.
    let env = story_env();

    let c0 = add_root(&env, TREE_A);
    let bench = eval_passed(&env, "evaluator", &c0, "benchmark");
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "ship",
            "--consider",
            &c0,
            "--choose",
            &c0,
            "--uses-eval",
            &bench,
            "--json",
        ],
    );
    let s0 = committed_id(&out);
    // A continuation resting on the selection: the descendant the compromise
    // must reach.
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            TREE_B,
            "--continues",
            &s0,
            "--parent",
            &c0,
            "--json",
        ],
    );
    let c1 = committed_id(&out);

    // Phase 1: clean.
    let out = validate_receipt(&env, "phase1.json");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("CLEAN"));

    // Phase 2: the benchmark was broken; its author retracts it.
    let out = run(
        &env,
        &[
            "retract",
            "--author",
            "evaluator",
            "--target",
            &bench,
            "--reason",
            "benchmark harness measured the wrong thing",
            "--json",
        ],
    );
    let _retraction = committed_id(&out);

    let out = validate_receipt(&env, "phase2.json");
    assert_eq!(out.status.code(), Some(2), "tainted receipts exit 2");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("TAINTED"));
    assert!(text.contains(&bench), "retracted id is reported");
    assert!(text.contains(&s0), "the selection that Used it is unsound");
    assert!(
        text.contains("standing-compromised") && text.contains(&c1),
        "the continuation descendant is compromised:\n{text}"
    );

    // Phase 3: reaffirm on fresh evidence; standing restores, Clean does not.
    let review = eval_passed(&env, "evaluator", &c0, "manual-review");
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "ship",
            "--consider",
            &c0,
            "--choose",
            &c0,
            "--uses-eval",
            &review,
            "--replaces",
            &s0,
            "--json",
        ],
    );
    let s1 = committed_id(&out);

    let out = validate_receipt(&env, "phase3.json");
    assert_eq!(
        out.status.code(),
        Some(2),
        "restored standing stays Tainted"
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("TAINTED"));
    assert!(
        text.contains("restorations") && text.contains(&s1),
        "the restoration is on the record:\n{text}"
    );
    assert!(
        !text.contains("standing-compromised"),
        "restored line is no longer compromised:\n{text}"
    );
}

#[test]
fn retract_ownership_battery() {
    // Cross-author rejected; admin accepted; a Retraction and a missing
    // target rejected; a second retraction of the same target accepted.
    let env = story_env();
    let c0 = add_root(&env, TREE_A);
    let bench = eval_passed(&env, "evaluator", &c0, "benchmark");

    // Cross-author: the agent may not retract the evaluator's record.
    let out = run(
        &env,
        &[
            "retract", "--author", "agent", "--target", &bench, "--reason", "not mine",
        ],
    );
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("AuthorRoleInvalid"));

    // Admin override: the human is in admin_retraction_actors.
    let out = run(
        &env,
        &[
            "retract",
            "--author",
            "human",
            "--target",
            &bench,
            "--reason",
            "admin override",
            "--json",
        ],
    );
    let retraction = committed_id(&out);

    // A retraction cannot be retracted.
    let out = run(
        &env,
        &[
            "retract",
            "--author",
            "human",
            "--target",
            &retraction,
            "--reason",
            "undo",
        ],
    );
    assert_eq!(out.status.code(), Some(65));

    // A target that resolves nowhere.
    let ghost = "f".repeat(64);
    let out = run(
        &env,
        &[
            "retract", "--author", "human", "--target", &ghost, "--reason", "ghost",
        ],
    );
    assert_eq!(out.status.code(), Some(65));

    // Redundant re-retraction of the same target is valid, not contradictory.
    let out = run(
        &env,
        &[
            "retract",
            "--author",
            "evaluator",
            "--target",
            &bench,
            "--reason",
            "again",
            "--json",
        ],
    );
    let _ = committed_id(&out);
}

#[test]
fn retract_requires_target_and_reason() {
    let env = story_env();
    let c0 = add_root(&env, TREE_A);

    let out = run(&env, &["retract", "--author", "agent", "--target", &c0]);
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--reason"));

    let out = run(
        &env,
        &["retract", "--author", "agent", "--reason", "no target"],
    );
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--target"));
}

// --- query: the RFC-0002 named set, and the section 8 gate proof -----------

/// Run a query with `--json` and parse the shared JSON shape.
fn query_json(env: &Env, args: &[&str]) -> Value {
    let mut full: Vec<&str> = args.to_vec();
    full.push("--json");
    let out = run(env, &full);
    assert!(
        out.status.success(),
        "query failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn eval_failed(env: &Env, author: &str, candidate: &str, criterion: &str) -> String {
    let out = run(
        env,
        &[
            "eval",
            "add",
            "--author",
            author,
            "--candidate",
            candidate,
            "--criterion",
            criterion,
            "--failed",
            "--json",
        ],
    );
    committed_id(&out)
}

fn derive_candidate(env: &Env, tree: &str, from: &str) -> String {
    let out = run(
        env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            tree,
            "--derives-from",
            from,
            "--json",
        ],
    );
    committed_id(&out)
}

/// RFC-0002 section 8, validation criterion 1 - the gate proof. The canary
/// best-of-N field test (2026-08-26) plus the retraction story, rewritten
/// against the named query set: every question the field test answered by
/// hand-walking records is answered here by `bellbook query` alone. No
/// records() walk, no manual ref-chasing, no receipt parsing - if any
/// assertion below needed one, the named set missed its shape.
#[test]
fn field_test_story_needs_zero_hand_walking() {
    let env = story_env();

    // The story: a baseline adopted on a benchmark, a best-of-N round over
    // its continuation, then the benchmark turns out broken and is
    // retracted, and the baseline is re-adopted on fresh evidence.
    let c0 = add_root(&env, TREE_A);
    let bench = eval_passed(&env, "evaluator", &c0, "benchmark");
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "adopt-baseline",
            "--consider",
            &c0,
            "--choose",
            &c0,
            "--uses-eval",
            &bench,
            "--json",
        ],
    );
    let s0 = committed_id(&out);
    let out = run(
        &env,
        &[
            "candidate",
            "add",
            "--author",
            "agent",
            "--git-tree",
            TREE_B,
            "--continues",
            &s0,
            "--parent",
            &c0,
            "--json",
        ],
    );
    let c1 = committed_id(&out);
    let c2 = derive_candidate(&env, "2222222222222222222222222222222222222222", &c1);
    let c3 = derive_candidate(&env, "3333333333333333333333333333333333333333", &c1);
    let e2 = eval_passed(&env, "evaluator", &c2, "unit-tests");
    let _e3 = eval_failed(&env, "evaluator", &c3, "unit-tests");
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "adopt",
            "--consider",
            &c2,
            &c3,
            "--choose",
            &c2,
            "--uses-eval",
            &e2,
            "--json",
        ],
    );
    let s1 = committed_id(&out);
    let out = run(
        &env,
        &[
            "retract",
            "--author",
            "evaluator",
            "--target",
            &bench,
            "--reason",
            "benchmark harness measured the wrong thing",
            "--json",
        ],
    );
    committed_id(&out);
    let review = eval_passed(&env, "evaluator", &c0, "benchmark-v2");
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "adopt-baseline",
            "--consider",
            &c0,
            "--choose",
            &c0,
            "--uses-eval",
            &review,
            "--replaces",
            &s0,
            "--json",
        ],
    );
    let s2 = committed_id(&out);

    // Q1 (field test: "which candidate won the round, on what evidence?").
    let v = query_json(&env, &["query", "selected", "adopt"]);
    let sels = v["selections"].as_array().unwrap();
    assert_eq!(sels.len(), 1);
    assert_eq!(sels[0]["selection"]["id"], Value::from(s1.clone()));
    assert_eq!(sels[0]["chosen"][0]["id"], Value::from(c2.clone()));
    assert_eq!(sels[0]["evidence"][0]["criterion"], "unit-tests");
    assert_eq!(sels[0]["evidence"][0]["outcome"], "passed");

    // Q2 ("what is the winner's full line of descent?").
    let v = query_json(&env, &["query", "descent", &c2]);
    let line = v["line"].as_array().unwrap();
    let step = |i: usize| {
        (
            line[i]["node"]["id"].as_str().unwrap(),
            line[i]["via"].as_str().unwrap(),
        )
    };
    assert_eq!(line.len(), 3);
    assert_eq!(step(0), (c1.as_str(), "derivation"));
    assert_eq!(step(1), (s0.as_str(), "continuation-anchor"));
    assert_eq!(step(2), (c0.as_str(), "parent"));

    // Q3 ("what does the line rest on?" - the question that exposed the
    // broken benchmark). The retracted evaluation surfaces, annotated.
    let v = query_json(&env, &["query", "evidence", &c2]);
    let rests = v["rests_on"].as_array().unwrap();
    assert_eq!(rests.len(), 1);
    assert_eq!(rests[0]["selection"]["id"], Value::from(s0.clone()));
    assert_eq!(rests[0]["evidence"][0]["node"]["id"], Value::from(bench));
    assert_eq!(
        rests[0]["evidence"][0]["node"]["retracted"],
        Value::from(true)
    );
    assert_eq!(rests[0]["evidence"][0]["criterion"], "benchmark");

    // Q4 ("what happened to the adoption after the retraction?"). The
    // anchor Selection is unsound and tainted; the re-adoption restored its
    // standing, on the record - and restoration is not erasure.
    let v = query_json(&env, &["query", "standing", &s0]);
    assert_eq!(v["node"]["standing"], "unsound");
    assert_eq!(v["node"]["tainted"], Value::from(true));
    assert_eq!(v["restorations"], Value::from(vec![s2]));

    // Q5 ("what is still open?"). The continuation was never considered;
    // the round's winner has no continuation yet. Nothing else.
    let v = query_json(&env, &["query", "frontier"]);
    let frontier = v["frontier"].as_array().unwrap();
    assert_eq!(frontier.len(), 2);
    assert_eq!(frontier[0]["node"]["id"], Value::from(c1));
    assert_eq!(frontier[0]["reason"], "unconsidered");
    assert_eq!(frontier[1]["node"]["id"], Value::from(c2.clone()));
    assert_eq!(frontier[1]["reason"], "selected-no-continuation");

    // Q6 ("who else was in the winner's generation?").
    let v = query_json(&env, &["query", "siblings", &c2]);
    let sibs = v["siblings"].as_array().unwrap();
    assert_eq!(sibs.len(), 1);
    assert_eq!(sibs[0]["id"], Value::from(c3));

    // Q7 ("everything downstream of the baseline?").
    let v = query_json(&env, &["query", "descendants", &c0]);
    let ids: Vec<&str> = v["descendants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 3, "c1, c2, c3 all descend from c0");
    assert!(ids.contains(&c2.as_str()));
}

#[test]
fn query_log_and_receipt_agree_byte_for_byte() {
    // The same query over the open log and over its exported receipt emits
    // identical bytes - the shared-shape claim (RFC-0002 C4), asserted.
    let env = story_env();
    let c0 = add_root(&env, TREE_A);
    let bench = eval_passed(&env, "evaluator", &c0, "benchmark");
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "ship",
            "--consider",
            &c0,
            "--choose",
            &c0,
            "--uses-eval",
            &bench,
            "--json",
        ],
    );
    committed_id(&out);

    let receipt = env._dir.path().join("r.json");
    let out = run(&env, &["export", "--out", receipt.to_str().unwrap()]);
    assert!(out.status.success());

    for args in [
        vec!["query", "descent", c0.as_str()],
        vec!["query", "frontier"],
        vec!["query", "selected", "ship"],
        vec!["query", "standing", c0.as_str()],
    ] {
        let mut log_args = args.clone();
        log_args.push("--json");
        let from_log = run(&env, &log_args);
        let mut receipt_cmd = bellbook();
        receipt_cmd.args(&args).arg("--json");
        receipt_cmd.arg("--receipt").arg(&receipt);
        let from_receipt = receipt_cmd.output().unwrap();
        assert!(from_log.status.success() && from_receipt.status.success());
        assert_eq!(
            from_log.stdout, from_receipt.stdout,
            "log/receipt divergence on {args:?}"
        );
    }
}

#[test]
fn query_error_battery() {
    let env = story_env();
    let c0 = add_root(&env, TREE_A);
    let bench = eval_passed(&env, "evaluator", &c0, "benchmark");

    // A rejected record is durably in the log but not addressable.
    let out = run(
        &env,
        &[
            "retract", "--author", "agent", "--target", &bench, "--reason", "not mine", "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(65));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let rejected = v["id"].as_str().unwrap().to_string();
    let out = run(&env, &["query", "standing", &rejected]);
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("rejected at commit"));

    // Kind mismatch: descent addresses candidates only.
    let out = run(&env, &["query", "descent", &bench]);
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a Candidate"));

    // Not found.
    let ghost = "f".repeat(64);
    let out = run(&env, &["query", "descent", &ghost]);
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));

    // Unknown query name.
    let out = run(&env, &["query", "best-descendant", &c0]);
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown query"));

    // Missing input, and both inputs at once.
    let out = bellbook().args(["query", "frontier"]).output().unwrap();
    assert_eq!(out.status.code(), Some(65));
    let receipt = env._dir.path().join("r.json");
    let out = run(&env, &["export", "--out", receipt.to_str().unwrap()]);
    assert!(out.status.success());
    let out = run(
        &env,
        &["query", "frontier", "--receipt", receipt.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("exactly one input"));

    // An unreadable receipt is refused with the validation problem, and
    // queries never answer over it.
    let bad = env._dir.path().join("bad.json");
    std::fs::write(&bad, b"not json").unwrap();
    let out = bellbook()
        .args(["query", "frontier", "--receipt", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not validate"));

    // A receipt embeds its rules; naming both is refused, not resolved.
    let out = bellbook()
        .args(["query", "frontier", "--receipt", receipt.to_str().unwrap()])
        .arg("--rules")
        .arg(&env.rules)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("embeds its rules"));

    // frontier takes no argument; id queries take exactly one.
    let out = run(&env, &["query", "frontier", &c0]);
    assert_eq!(out.status.code(), Some(65));
    let out = run(&env, &["query", "descent"]);
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires a record id"));
}

#[test]
fn query_human_rendering_reports_annotations() {
    // The default (non-JSON) rendering carries the same annotations: after
    // a retraction, the human output says so in words.
    let env = story_env();
    let c0 = add_root(&env, TREE_A);
    let bench = eval_passed(&env, "evaluator", &c0, "benchmark");
    let out = run(
        &env,
        &[
            "select",
            "--author",
            "agent",
            "--objective",
            "ship",
            "--consider",
            &c0,
            "--choose",
            &c0,
            "--uses-eval",
            &bench,
            "--json",
        ],
    );
    let s0 = committed_id(&out);
    let out = run(
        &env,
        &[
            "retract",
            "--author",
            "evaluator",
            "--target",
            &bench,
            "--reason",
            "broken",
            "--json",
        ],
    );
    committed_id(&out);

    let out = run(&env, &["query", "standing", &s0]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        text.contains("unsound") && text.contains("tainted"),
        "{text}"
    );

    let out = run(&env, &["query", "evidence", &s0]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        text.contains("retracted") && text.contains("benchmark -> passed"),
        "{text}"
    );
}
