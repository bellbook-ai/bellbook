//! Profile vectors for `delivery-receipt-v1` (RFC-0003 section 4.6, SPEC
//! section 12.2), generated from and checked against the reference
//! implementation.
//!
//! Writes `spec/profiles/delivery-receipt-v1/profile.json` (the clause table
//! the profile hash commits to) and `cases.json` (receipts paired with every
//! profile result validation reports for them) with `UPDATE_CONFORMANCE=1`;
//! otherwise checks the committed files for drift and re-derives every stored
//! result from the stored receipt - the contract an independent
//! implementation follows. The cases are the fraud battery: one conformant
//! claim in each honest shape, and one rejecting case per clause D0-D7,
//! including the canonical forgeries (a claim over a non-passing evaluation
//! with every digest consistent; a genuine passing claim reattached to another
//! candidate). Profile vectors live apart from the core corpus so a profile
//! can never destabilize core conformance (RFC-0003 C5).

#![cfg(feature = "persist")]

use bellbook::*;
use std::path::PathBuf;

const SPACE: [u8; 32] = [13u8; 32];
const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const OTHER_TREE: &str = "1111111111111111111111111111111111111111";
const DIST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const PROCEDURE: [u8; 32] = [0x51u8; 32];
const INPUT: [u8; 32] = [0x52u8; 32];

fn baseline_rules() -> VerifierRules {
    roles(VerifierRules::new(SPACE, 200)).with_baseline_thresholds()
}

fn roles(rules: VerifierRules) -> VerifierRules {
    rules
        .with_author_role("human", AuthorType::User)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider)
        .with_author_role("auditor", AuthorType::Provider)
        .with_author_role("runner", AuthorType::Executor)
}

fn tree_ref(digest: &str) -> ArtifactRef {
    ArtifactRef {
        scheme: "git-tree-sha1".into(),
        digest: digest.into(),
        name: Some("src".into()),
    }
}

fn dist_ref() -> ArtifactRef {
    ArtifactRef {
        scheme: "sha256-bytes".into(),
        digest: DIST.into(),
        name: Some("dist.tar".into()),
    }
}

/// A log under construction: the writer, its state, and the rules, with
/// one builder per record shape the battery needs. Every commit is asserted
/// accepted, so a vector is always a *valid* history whose claim the
/// profile then judges - the fraud battery is about claims, not forgeries
/// the core already rejects.
struct Log {
    _dir: tempfile::TempDir,
    w: LogWriter,
    st: State,
    rules: VerifierRules,
}

impl Log {
    fn new(rules: VerifierRules) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let w = LogWriter::open(dir.path(), &rules).unwrap();
        Log {
            _dir: dir,
            w,
            st: State::default(),
            rules,
        }
    }

    fn author(&self, id: &str) -> Author {
        Author {
            id: id.into(),
            type_: self.rules.author_roles[id],
            signature: None,
        }
    }

    fn commit(
        &mut self,
        who: &str,
        kind: Kind,
        schema: &str,
        data: Vec<u8>,
        refs: Vec<Ref>,
    ) -> RecordId {
        let (id, v) = self
            .w
            .commit(
                Proposal {
                    space: SPACE,
                    thread: SPACE,
                    author: self.author(who),
                    kind,
                    schema: schema_id(schema),
                    data,
                    refs,
                },
                &self.rules,
                &mut self.st,
            )
            .unwrap();
        assert_eq!(
            v.result,
            VerdictResult::Accept,
            "{kind:?} must commit: {:?}",
            v.reason
        );
        id
    }

    fn request(&mut self) -> RecordId {
        let data = encode(&RequestData {
            objective: "ship the bound build".into(),
            scope: SPACE,
            attachments: vec![],
            parent_request_id: None,
        })
        .unwrap();
        self.commit("human", Kind::Request, SCHEMA_REQUEST, data, vec![])
    }

    fn requirement(&mut self, who: &str, req: RecordId, key: &str, required: bool) -> RecordId {
        let provenance = if self.rules.author_roles[who] == AuthorType::User {
            Provenance::UserAuthored
        } else {
            Provenance::Derived
        };
        let data = encode(&RequirementData {
            key: key.into(),
            description: format!("{key} holds"),
            required,
            expected_evidence: None,
            provenance,
        })
        .unwrap();
        self.commit(
            who,
            Kind::Requirement,
            SCHEMA_REQUIREMENT,
            data,
            vec![cause(req)],
        )
    }

    fn candidate(
        &mut self,
        who: &str,
        tree: &str,
        artifacts: Option<Vec<ArtifactRef>>,
    ) -> RecordId {
        let data = encode(&CandidateData {
            artifacts,
            source: SourceBinding {
                git: GitSource {
                    algo: SourceAlgo::Sha1,
                    tree: tree.into(),
                    commit: None,
                },
                manifest_hash: None,
                binding: BindingMode::Reported,
            },
            basis: CandidateBasis::Root,
            parent: None,
            note: None,
        })
        .unwrap();
        self.commit(who, Kind::Candidate, SCHEMA_CANDIDATE, data, vec![])
    }

    /// An extended evaluation: `bound` is `(procedure_hash, input_hash)`
    /// present or absent, `basis` the declared basis.
    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        &mut self,
        who: &str,
        candidate: RecordId,
        criterion: &str,
        outcome: EvaluationOutcomeV2,
        requirements: Vec<RecordId>,
        evidence: Vec<ArtifactRef>,
        bound: bool,
        basis: Basis,
    ) -> RecordId {
        let mut requirements = requirements;
        requirements.sort();
        let mut refs = vec![use_r(candidate)];
        refs.extend(requirements.iter().map(|r| use_r(*r)));
        let data = encode(&EvaluationDataV2 {
            candidate,
            criterion: criterion.into(),
            procedure: None,
            outcome,
            evaluator: DeciderBinding {
                id: format!("{who}-harness"),
                version: Some("1.0".into()),
                procedure_hash: bound.then_some(PROCEDURE),
                input_hash: bound.then_some(INPUT),
            },
            basis,
            evidence,
            requirements,
        })
        .unwrap();
        self.commit(who, Kind::Evaluation, SCHEMA_EVALUATION_V2, data, refs)
    }

    fn evaluate_v1(&mut self, who: &str, candidate: RecordId) -> RecordId {
        let data = encode(&EvaluationData {
            candidate,
            criterion: "unit-tests".into(),
            procedure: None,
            outcome: EvaluationOutcome::Passed,
        })
        .unwrap();
        self.commit(
            who,
            Kind::Evaluation,
            SCHEMA_EVALUATION,
            data,
            vec![use_r(candidate)],
        )
    }

    fn select(
        &mut self,
        who: &str,
        considered: Vec<RecordId>,
        chosen: Vec<RecordId>,
        uses: Vec<RecordId>,
    ) -> RecordId {
        let mut refs: Vec<Ref> = chosen.iter().map(|c| require(*c)).collect();
        refs.extend(uses.iter().map(|e| use_r(*e)));
        let data = encode(&SelectionData {
            objective: "ship".into(),
            considered,
            outcome: SelectionOutcome::Selected { candidates: chosen },
            rationale: None,
        })
        .unwrap();
        self.commit(who, Kind::Selection, SCHEMA_SELECTION, data, refs)
    }

    fn retract(&mut self, who: &str, target: RecordId) -> RecordId {
        let data = encode(&RetractionData {
            target_id: target,
            reason: "the judgment was wrong".into(),
        })
        .unwrap();
        self.commit(
            who,
            Kind::Retraction,
            SCHEMA_RETRACTION,
            data,
            vec![cause(target)],
        )
    }

    /// A producer result binding `artifacts`, reached through the activity
    /// kinds: a capability for the agent, an action under the request, and
    /// the executor's result closing it.
    fn result_with_artifacts(&mut self, req: RecordId, artifacts: Vec<ArtifactRef>) -> RecordId {
        let cap = encode(&CapabilityData {
            actor_id: "agent".into(),
            action_class: "build".into(),
            scope: SPACE,
            mode: CapabilityMode::Auto,
            expiry: None,
        })
        .unwrap();
        let cap = self.commit("human", Kind::Capability, SCHEMA_CAPABILITY, cap, vec![]);
        let action = encode(&ActionData {
            request_id: req,
            action_class: "build".into(),
            scope: SPACE,
            exec_mode: ExecMode::Internal,
            params: serde_json::json!({}),
        })
        .unwrap();
        let action = self.commit(
            "agent",
            Kind::Action,
            SCHEMA_ACTION,
            action,
            vec![require(cap)],
        );
        let result = encode(&ResultData {
            artifacts: Some(artifacts),
            action_id: action,
            status: ResultStatus::Success,
            output: "built".into(),
        })
        .unwrap();
        self.commit(
            "runner",
            Kind::Result,
            SCHEMA_RESULT,
            result,
            vec![cause(action)],
        )
    }

    fn receipt(&self, declare: &[&str]) -> Receipt {
        Receipt::new(self.w.records(), &self.rules)
            .with_declared_profiles(declare)
            .unwrap()
    }
}

fn cause(t: RecordId) -> Ref {
    Ref {
        type_: RefType::Cause,
        target: t,
    }
}
fn use_r(t: RecordId) -> Ref {
    Ref {
        type_: RefType::Use,
        target: t,
    }
}
fn require(t: RecordId) -> Ref {
    Ref {
        type_: RefType::Require,
        target: t,
    }
}

const BOTH: [&str; 2] = [BELLBOOK_CORE_V1, DELIVERY_RECEIPT_V1];

/// The honest story every rejecting case perturbs: a request, a required
/// user-authored requirement and an informational derived one, a candidate
/// bound to its tree, a passing recomputed evaluation of the required
/// requirement over that tree, a not-run declared evaluation of the
/// informational one, and the claim.
struct Story {
    log: Log,
    req: RecordId,
    r1: RecordId,
    c0: RecordId,
    e1: RecordId,
    e2: RecordId,
}

fn story_until_claim(rules: VerifierRules) -> Story {
    let mut log = Log::new(rules);
    let req = log.request();
    let r1 = log.requirement("human", req, "R1", true);
    let r2 = log.requirement("agent", req, "R2", false);
    let c0 = log.candidate("agent", TREE, Some(vec![tree_ref(TREE)]));
    let e1 = log.evaluate(
        "evaluator",
        c0,
        "unit-tests",
        EvaluationOutcomeV2::Passed,
        vec![r1],
        vec![tree_ref(TREE)],
        true,
        Basis::Recomputed,
    );
    let e2 = log.evaluate(
        "evaluator",
        c0,
        "lint",
        EvaluationOutcomeV2::NotRun,
        vec![r2],
        vec![tree_ref(TREE)],
        true,
        Basis::Declared,
    );
    Story {
        log,
        req,
        r1,
        c0,
        e1,
        e2,
    }
}

fn honest_story() -> (Story, RecordId) {
    let mut s = story_until_claim(baseline_rules());
    let s0 = s
        .log
        .select("agent", vec![s.c0], vec![s.c0], vec![s.e1, s.e2]);
    (s, s0)
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ClauseExpect {
    id: String,
    passed: bool,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ProfileExpect {
    id: String,
    status: ProfileStatus,
    declared: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    declaration_matches: Option<bool>,
    clauses: Vec<ClauseExpect>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct CaseExpect {
    profiles: Vec<ProfileExpect>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ProfileCase {
    name: String,
    description: String,
    receipt: Receipt,
    expect: CaseExpect,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct CasesFile {
    profile: String,
    hash: Hash256,
    description: String,
    cases: Vec<ProfileCase>,
}

fn surface(p: &ProfileResult) -> ProfileExpect {
    ProfileExpect {
        id: p.id.clone(),
        status: p.status,
        declared: p.declared,
        declaration_matches: p.declaration_matches,
        clauses: p
            .clauses
            .iter()
            .map(|c| ClauseExpect {
                id: c.id.clone(),
                passed: c.passed,
            })
            .collect(),
    }
}

fn report_for(receipt: &Receipt) -> Report {
    let bytes = receipt.to_bytes().unwrap();
    validate_with_profiles(&bytes, &ValidationLimits::default(), &[DELIVERY_RECEIPT_V1])
}

fn expect_for(receipt: &Receipt) -> CaseExpect {
    CaseExpect {
        profiles: report_for(receipt).profiles.iter().map(surface).collect(),
    }
}

fn build_cases() -> Vec<ProfileCase> {
    let mut cases = Vec::new();
    let mut push = |name: &str, description: &str, receipt: Receipt| {
        let expect = expect_for(&receipt);
        cases.push(ProfileCase {
            name: name.into(),
            description: description.into(),
            receipt,
            expect,
        });
    };

    // --- conformant claims -------------------------------------------------
    {
        let (s, _) = honest_story();
        push(
            "conformant-claim",
            "The honest story: a required user-authored requirement covered by a passing, recomputed, fully bound evaluation over the candidate's own tree; an informational requirement with a not-run evaluation (allowed: it is not required); producer and evaluator distinct; the baseline declared and met. Weakest basis reported as declared.",
            s.log.receipt(&BOTH),
        );
    }
    {
        // The baseline evaluated as the 0.7 fallback when not declared.
        let (s, _) = honest_story();
        push(
            "conformant-claim-baseline-undeclared",
            "The honest story with only delivery-receipt-v1 declared: D6 evaluates bellbook-core-v1 as the fallback and it conforms.",
            s.log.receipt(&[DELIVERY_RECEIPT_V1]),
        );
    }
    {
        // Evidence bound by an accepted Result rather than the candidate.
        let mut s = story_until_claim(baseline_rules());
        s.log.result_with_artifacts(s.req, vec![dist_ref()]);
        let e3 = s.log.evaluate(
            "auditor",
            s.c0,
            "packaging",
            EvaluationOutcomeV2::Passed,
            vec![s.r1],
            vec![dist_ref()],
            true,
            Basis::Recomputed,
        );
        s.log
            .select("agent", vec![s.c0], vec![s.c0], vec![s.e1, s.e2, e3]);
        push(
            "conformant-evidence-from-result",
            "An evaluation cites an artifact the candidate does not carry but an accepted Result in the same thread does: evidence on the record through the producer's result (RFC-0003 decision 7).",
            s.log.receipt(&BOTH),
        );
    }
    {
        // Two claims for one request: the latest sound one is evaluated and
        // the earlier one reported superseded.
        let (mut s, _s0) = honest_story();
        let e1b = s.log.evaluate(
            "auditor",
            s.c0,
            "unit-tests",
            EvaluationOutcomeV2::Passed,
            vec![s.r1],
            vec![tree_ref(TREE)],
            true,
            Basis::Recomputed,
        );
        s.log
            .select("agent", vec![s.c0], vec![s.c0], vec![e1b, s.e2]);
        push(
            "conformant-latest-claim-supersedes-earlier",
            "Two accepted claims for the same request: the latest sound one is evaluated and conforms; the earlier one is reported superseded in D0 (RFC-0003 decision 8).",
            s.log.receipt(&BOTH),
        );
    }

    // --- the fraud battery: one rejecting case per clause ------------------
    {
        let mut log = Log::new(baseline_rules());
        let c0 = log.candidate("agent", TREE, Some(vec![tree_ref(TREE)]));
        let e = log.evaluate_v1("evaluator", c0);
        log.select("agent", vec![c0], vec![c0], vec![e]);
        push(
            "no-claim-fails-d0",
            "A Clean line whose selection uses only a v1 evaluation bound to no requirement: there is no delivery claim, so D0 fails and every other clause has nothing to evaluate. A best-of-N receipt is not a delivery receipt.",
            log.receipt(&BOTH),
        );
    }
    {
        let (mut s, _) = honest_story();
        s.log.requirement("human", s.req, "R3", true);
        push(
            "uncovered-required-requirement-fails-d1",
            "A required requirement recorded after the claim has no passing evaluation among the claim's evaluations: coverage is judged at the receipt head, so D1 fails until the claim is re-made (RFC-0003 decision 6).",
            s.log.receipt(&BOTH),
        );
    }
    {
        let mut s = story_until_claim(baseline_rules());
        let e1b = s.log.evaluate(
            "auditor",
            s.c0,
            "integration-tests",
            EvaluationOutcomeV2::Failed,
            vec![s.r1],
            vec![tree_ref(TREE)],
            true,
            Basis::Recomputed,
        );
        s.log
            .select("agent", vec![s.c0], vec![s.c0], vec![s.e1, e1b, s.e2]);
        push(
            "non-passing-evaluation-over-required-requirement-fails-d2",
            "The required requirement is covered by one passing evaluation (D1 holds), but the claim also uses a failed evaluation of it: truthful completion fails. A claim cannot select the passing judgment and carry the failing one along.",
            s.log.receipt(&BOTH),
        );
    }
    {
        let mut log = Log::new(baseline_rules());
        let req = log.request();
        let r1 = log.requirement("human", req, "R1", true);
        let c0 = log.candidate("agent", TREE, Some(vec![tree_ref(TREE)]));
        let e1 = log.evaluate(
            "evaluator",
            c0,
            "unit-tests",
            EvaluationOutcomeV2::Failed,
            vec![r1],
            vec![tree_ref(TREE)],
            true,
            Basis::Recomputed,
        );
        log.select("agent", vec![c0], vec![c0], vec![e1]);
        push(
            "forged-claim-over-failed-evaluation-fails-d1-d2",
            "The canonical forgery: every id and digest is consistent and the log replays Clean, but the only evaluation of the required requirement failed and the selection claims the candidate anyway. Rejected on replay of the claim (D1 and D2), whatever its hashes say.",
            log.receipt(&BOTH),
        );
    }
    {
        let mut s = story_until_claim(baseline_rules());
        let c1 = s
            .log
            .candidate("agent", OTHER_TREE, Some(vec![tree_ref(OTHER_TREE)]));
        s.log
            .select("agent", vec![s.c0, c1], vec![c1], vec![s.e1, s.e2]);
        push(
            "rebinding-to-another-candidate-fails-d3",
            "A genuine passing evaluation of one candidate reattached to a claim for another: the claim chooses a candidate the evaluations did not judge, so binding equality fails.",
            s.log.receipt(&BOTH),
        );
    }
    {
        let mut log = Log::new(baseline_rules());
        let req = log.request();
        let r1 = log.requirement("human", req, "R1", true);
        let c0 = log.candidate("agent", TREE, Some(vec![tree_ref(TREE)]));
        let e1 = log.evaluate(
            "evaluator",
            c0,
            "unit-tests",
            EvaluationOutcomeV2::Passed,
            vec![r1],
            vec![tree_ref(OTHER_TREE)],
            true,
            Basis::Recomputed,
        );
        log.select("agent", vec![c0], vec![c0], vec![e1]);
        push(
            "evidence-not-on-record-fails-d3",
            "The evaluation cites an artifact neither the candidate nor any accepted Result in the thread carries: evidence conjured outside the record fails binding equality.",
            log.receipt(&BOTH),
        );
    }
    {
        let mut log = Log::new(baseline_rules());
        let req = log.request();
        let r1 = log.requirement("human", req, "R1", true);
        let c0 = log.candidate("agent", TREE, Some(vec![tree_ref(TREE)]));
        let e1 = log.evaluate(
            "evaluator",
            c0,
            "unit-tests",
            EvaluationOutcomeV2::Passed,
            vec![r1],
            vec![],
            true,
            Basis::Recomputed,
        );
        log.select("agent", vec![c0], vec![c0], vec![e1]);
        push(
            "empty-evidence-fails-d3",
            "The evaluation binds to the requirement but cites no evidence at all: a judgment over nothing does not deliver.",
            log.receipt(&BOTH),
        );
    }
    {
        let mut log = Log::new(baseline_rules());
        let req = log.request();
        let r1 = log.requirement("human", req, "R1", true);
        let c0 = log.candidate("agent", TREE, Some(vec![tree_ref(TREE)]));
        let e1 = log.evaluate(
            "agent",
            c0,
            "unit-tests",
            EvaluationOutcomeV2::Passed,
            vec![r1],
            vec![tree_ref(TREE)],
            true,
            Basis::Recomputed,
        );
        log.select("agent", vec![c0], vec![c0], vec![e1]);
        push(
            "self-judged-fails-d4",
            "The producer of the candidate authored the evaluation the claim rests on: producer and evaluator must be distinct actors.",
            log.receipt(&BOTH),
        );
    }
    {
        let mut log = Log::new(baseline_rules());
        let req = log.request();
        let r1 = log.requirement("human", req, "R1", true);
        let c0 = log.candidate("agent", TREE, Some(vec![tree_ref(TREE)]));
        let e1 = log.evaluate(
            "evaluator",
            c0,
            "unit-tests",
            EvaluationOutcomeV2::Passed,
            vec![r1],
            vec![tree_ref(TREE)],
            false,
            Basis::Declared,
        );
        log.select("agent", vec![c0], vec![c0], vec![e1]);
        push(
            "missing-decider-binding-fails-d5",
            "The evaluation names its evaluator but carries neither procedure_hash nor input_hash: the decider binding is incomplete.",
            log.receipt(&BOTH),
        );
    }
    {
        let s = {
            let mut s = story_until_claim(roles(VerifierRules::new(SPACE, 200)));
            s.log
                .select("agent", vec![s.c0], vec![s.c0], vec![s.e1, s.e2]);
            s
        };
        push(
            "baseline-not-met-fails-d6",
            "Valid rules without the baseline evidence thresholds: the claim itself holds, but the receipt does not conform to bellbook-core-v1, so no capability profile is met.",
            s.log.receipt(&[DELIVERY_RECEIPT_V1]),
        );
    }
    {
        let (s, _) = honest_story();
        let mut receipt = s.log.receipt(&[DELIVERY_RECEIPT_V1]);
        receipt.profiles.insert(
            0,
            ProfileRef {
                id: BELLBOOK_CORE_V1.into(),
                version: 1,
                hash: [0xAB; 32],
            },
        );
        push(
            "stale-baseline-declaration-fails-d6",
            "The receipt declares bellbook-core-v1 with a hash that is not the published table's: the baseline evaluates Conformant, but the declaration does not name the table that was checked, so the capability profile is not met.",
            receipt,
        );
    }
    {
        let (mut s, _) = honest_story();
        s.log.retract("evaluator", s.e1);
        push(
            "retracted-evaluation-fails-d7",
            "The evaluator retracts the passing evaluation: the selection is unsound and tainted, so standing fails (and coverage with it). Tainted history is on the record; the claim no longer holds.",
            s.log.receipt(&BOTH),
        );
    }

    cases
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("spec")
        .join("profiles")
        .join(DELIVERY_RECEIPT_V1)
}

fn write_json<T: serde::Serialize>(path: &PathBuf, value: &T) {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap() + "\n").unwrap();
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> T {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} (regenerate with UPDATE_CONFORMANCE=1)",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap()
}

#[test]
fn delivery_vectors() {
    let table = delivery_v1_table();
    let file = CasesFile {
        profile: DELIVERY_RECEIPT_V1.into(),
        hash: profile_hash(&table),
        description: "delivery-receipt-v1 profile vectors: each receipt paired with every profile result validation reports for it (bellbook-core-v1 where declared, then delivery-receipt-v1); conformant claims in each honest shape and the fraud battery - one rejecting case per clause D0-D7, including the canonical forgeries.".into(),
        cases: build_cases(),
    };
    let d = dir();

    if std::env::var("UPDATE_CONFORMANCE").is_ok() {
        std::fs::create_dir_all(&d).unwrap();
        write_json(&d.join("profile.json"), &table);
        write_json(&d.join("cases.json"), &file);
        return;
    }

    let stored_table: ProfileTable = read_json(&d.join("profile.json"));
    assert_eq!(
        stored_table, table,
        "profile table drifted; regenerate with UPDATE_CONFORMANCE=1"
    );
    let stored: CasesFile = read_json(&d.join("cases.json"));
    assert_eq!(
        stored, file,
        "profile vectors drifted; regenerate with UPDATE_CONFORMANCE=1"
    );

    // Correctness: re-derive each stored result from the stored receipt.
    assert_eq!(stored.hash, profile_hash(&stored_table));
    let mut outcomes = std::collections::BTreeSet::new();
    let mut failing = std::collections::BTreeSet::new();
    let mut superseded_seen = false;
    for c in &stored.cases {
        let report = report_for(&c.receipt);
        let got: Vec<ProfileExpect> = report.profiles.iter().map(surface).collect();
        assert_eq!(got, c.expect.profiles, "case {}", c.name);
        let p = report
            .profiles
            .iter()
            .find(|p| p.id == DELIVERY_RECEIPT_V1)
            .unwrap_or_else(|| panic!("case {}: no delivery result", c.name));
        assert_eq!(p.hash, stored.hash, "case {}", c.name);
        // Every conformant case replays Clean; the verdict is never what a
        // profile judges, and the fraud battery is about valid histories.
        assert_ne!(report.status, ValidationStatus::Invalid, "case {}", c.name);
        outcomes.insert(p.status);
        failing.extend(p.clauses.iter().filter(|k| !k.passed).map(|k| k.id.clone()));
        superseded_seen |= p
            .clauses
            .iter()
            .any(|k| k.id == "D0" && k.detail.contains("superseded"));
    }
    // Coverage: both outcomes, a rejecting vector for every clause, and the
    // superseded-claim report.
    assert!(outcomes.contains(&ProfileStatus::Conformant));
    assert!(outcomes.contains(&ProfileStatus::NonConformant));
    for id in ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"] {
        assert!(failing.contains(id), "no rejecting vector for {id}");
    }
    assert!(superseded_seen, "no vector reports a superseded claim");
}
