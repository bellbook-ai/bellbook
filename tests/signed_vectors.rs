//! Profile vectors for `bellbook-core-signed-v1` (RFC-0003 section 4.5, SPEC
//! section 12.2), generated from and checked against the reference
//! implementation.
//!
//! Writes `spec/profiles/bellbook-core-signed-v1/profile.json` (the clause
//! table the profile hash commits to) and `cases.json` (receipts paired with
//! every profile result validation reports for them) with
//! `UPDATE_CONFORMANCE=1`; otherwise checks the committed files for drift and
//! re-derives every stored result from the stored receipt - the contract an
//! independent implementation follows. The cases are: the signed tier met in
//! each honest shape (baseline declared, baseline as the fallback, a
//! delivery claim judged under the signed tier, a Tainted history, an unused
//! unattested evaluation), one rejecting case per clause S0-S3, a stale
//! declaration, and an Invalid receipt. Every record an author with pinned
//! keys writes is really signed with that key: the vectors carry Ed25519
//! signatures an independent implementation must verify. Profile vectors
//! live apart from the core corpus so a profile can never destabilize core
//! conformance (RFC-0003 C5).

#![cfg(feature = "persist")]

use bellbook::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

const SPACE: [u8; 32] = [17u8; 32];
const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const PROCEDURE: [u8; 32] = [0x61u8; 32];
const INPUT: [u8; 32] = [0x62u8; 32];

/// Deterministic signer per actor: the vectors are reproducible byte for
/// byte, and the keys are test keys with no other use.
fn signer(who: &str) -> Ed25519Signer {
    let seed = match who {
        "human" => [21u8; 32],
        "agent" => [22u8; 32],
        "evaluator" => [23u8; 32],
        other => panic!("no signer for {other}"),
    };
    Ed25519Signer::from_secret_bytes(&seed)
}

fn roles(rules: VerifierRules) -> VerifierRules {
    rules
        .with_author_role("human", AuthorType::User)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider)
}

fn baseline_rules() -> VerifierRules {
    roles(VerifierRules::new(SPACE, 200)).with_baseline_thresholds()
}

/// The rule shape the signed tier asks for: signatures required on every
/// evolution kind, and every actor's keys pinned.
fn signed_rules() -> VerifierRules {
    let mut rules = baseline_rules();
    for kind in SIGNED_TIER_KINDS {
        rules.signature_required_kinds.insert(kind);
    }
    for who in ["human", "agent", "evaluator"] {
        rules
            .author_keys
            .insert(who.into(), [signer(who).public_key()].into_iter().collect());
    }
    rules
}

fn tree_ref(digest: &str) -> ArtifactRef {
    ArtifactRef {
        scheme: "git-tree-sha1".into(),
        digest: digest.into(),
        name: Some("src".into()),
    }
}

/// A log under construction whose authors sign. Every actor with a signer
/// signs every record it writes; an actor without one writes unsigned. Every
/// commit is asserted accepted: a vector is always a *valid* history the
/// profile then judges (the Invalid case is produced by editing a receipt
/// after the fact, as an attacker would).
struct Log {
    _dir: tempfile::TempDir,
    w: LogWriter,
    st: State,
    rules: VerifierRules,
    signers: BTreeMap<&'static str, Ed25519Signer>,
}

impl Log {
    fn new(rules: VerifierRules, signing: &[&'static str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let w = LogWriter::open(dir.path(), &rules).unwrap();
        Log {
            _dir: dir,
            w,
            st: State::default(),
            rules,
            signers: signing.iter().map(|who| (*who, signer(who))).collect(),
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
        let proposal = Proposal {
            space: SPACE,
            thread: SPACE,
            author: self.author(who),
            kind,
            schema: schema_id(schema),
            data,
            refs,
        };
        let (id, v) = match self.signers.get(who) {
            Some(s) => self
                .w
                .commit_signed(proposal, &self.rules, &mut self.st, s)
                .unwrap(),
            None => self.w.commit(proposal, &self.rules, &mut self.st).unwrap(),
        };
        assert_eq!(
            v.result,
            VerdictResult::Accept,
            "{kind:?} by {who} must commit: {:?}",
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

    fn candidate(&mut self, who: &str, tree: &str) -> RecordId {
        let data = encode(&CandidateData {
            artifacts: Some(vec![tree_ref(tree)]),
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

    /// An extended evaluation under `schema` (`SCHEMA_EVALUATION_ATTESTED`
    /// or `SCHEMA_EVALUATION_V2`), fully bound, recomputed.
    fn evaluate(
        &mut self,
        who: &str,
        schema: &str,
        candidate: RecordId,
        criterion: &str,
        outcome: EvaluationOutcomeV2,
        requirements: Vec<RecordId>,
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
                procedure_hash: Some(PROCEDURE),
                input_hash: Some(INPUT),
            },
            basis: Basis::Recomputed,
            evidence: vec![tree_ref(TREE)],
            requirements,
        })
        .unwrap();
        self.commit(who, Kind::Evaluation, schema, data, refs)
    }

    fn evaluate_v1(&mut self, who: &str, candidate: RecordId) -> RecordId {
        let data = encode(&EvaluationData {
            candidate,
            criterion: "smoke".into(),
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

    fn select(&mut self, who: &str, chosen: RecordId, uses: Vec<RecordId>) -> RecordId {
        let mut refs: Vec<Ref> = vec![require(chosen)];
        refs.extend(uses.iter().map(|e| use_r(*e)));
        let data = encode(&SelectionData {
            objective: "ship".into(),
            considered: vec![chosen],
            outcome: SelectionOutcome::Selected {
                candidates: vec![chosen],
            },
            rationale: None,
        })
        .unwrap();
        self.commit(who, Kind::Selection, SCHEMA_SELECTION, data, refs)
    }

    fn retract(&mut self, who: &str, target: RecordId) -> RecordId {
        let data = encode(&RetractionData {
            target_id: target,
            reason: "superseded by a later run".into(),
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

const ALL_SIGNERS: [&str; 3] = ["human", "agent", "evaluator"];
const CORE_AND_SIGNED: [&str; 2] = [BELLBOOK_CORE_V1, BELLBOOK_CORE_SIGNED_V1];
const ALL_THREE: [&str; 3] = [
    BELLBOOK_CORE_V1,
    BELLBOOK_CORE_SIGNED_V1,
    DELIVERY_RECEIPT_V1,
];

/// The honest signed story: a request, a required user-authored requirement
/// and an informational derived one, a candidate bound to its tree, two
/// attested evaluations by a distinct evaluator, and the claim - every
/// record signed by its pinned author.
struct Story {
    log: Log,
    c0: RecordId,
    e1: RecordId,
    e2: RecordId,
}

fn story_until_claim(rules: VerifierRules, signing: &[&'static str], eval_schema: &str) -> Story {
    let mut log = Log::new(rules, signing);
    let req = log.request();
    let r1 = log.requirement("human", req, "R1", true);
    let r2 = log.requirement("agent", req, "R2", false);
    let c0 = log.candidate("agent", TREE);
    let e1 = log.evaluate(
        "evaluator",
        eval_schema,
        c0,
        "unit-tests",
        EvaluationOutcomeV2::Passed,
        vec![r1],
    );
    let e2 = log.evaluate(
        "evaluator",
        eval_schema,
        c0,
        "lint",
        EvaluationOutcomeV2::NotRun,
        vec![r2],
    );
    Story { log, c0, e1, e2 }
}

fn honest_story() -> Story {
    let mut s = story_until_claim(signed_rules(), &ALL_SIGNERS, SCHEMA_EVALUATION_ATTESTED);
    s.log.select("agent", s.c0, vec![s.e1, s.e2]);
    s
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
    status: ValidationStatus,
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
    validate_with_profiles(
        &bytes,
        &ValidationLimits::default(),
        &[BELLBOOK_CORE_SIGNED_V1],
    )
}

fn expect_for(receipt: &Receipt) -> CaseExpect {
    let report = report_for(receipt);
    CaseExpect {
        status: report.status,
        profiles: report.profiles.iter().map(surface).collect(),
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

    // --- the signed tier met -----------------------------------------------
    push(
        "conformant-signed",
        "The honest signed story: the rules require a signature on every evolution kind and pin every actor's key; every record is signed by its pinned author; the two evaluations the claim uses are attested. Baseline and signed tier declared and met.",
        honest_story().log.receipt(&CORE_AND_SIGNED),
    );
    push(
        "conformant-signed-baseline-undeclared",
        "The honest signed story declaring only bellbook-core-signed-v1: S0 evaluates the baseline as the fallback and it conforms.",
        honest_story().log.receipt(&[BELLBOOK_CORE_SIGNED_V1]),
    );
    push(
        "conformant-delivery-under-signed-tier",
        "The honest signed story is also a delivery claim: all three profiles declared; delivery-receipt-v1 D6 evaluates the declared baseline, and the claim's attested evaluations satisfy S3. The capability profile a claim is judged under may be either tier.",
        honest_story().log.receipt(&ALL_THREE),
    );
    {
        // Tainted history is still conformant: an unused evaluation is
        // retracted by its author, which also exercises the signed
        // Retraction kind under S2.
        let mut s = honest_story();
        let extra = s.log.evaluate(
            "evaluator",
            SCHEMA_EVALUATION_ATTESTED,
            s.c0,
            "benchmark",
            EvaluationOutcomeV2::Passed,
            vec![],
        );
        s.log.retract("evaluator", extra);
        push(
            "conformant-signed-tainted-history",
            "An attested evaluation no selection used is retracted by its signing author: the receipt is Tainted, which the baseline admits (B1), and the signed Retraction counts under S2. Still conformant.",
            s.log.receipt(&CORE_AND_SIGNED),
        );
    }
    {
        // An unattested evaluation no selection uses is allowed: S3 is about
        // what claims rest on.
        let mut s = honest_story();
        s.log.evaluate_v1("evaluator", s.c0);
        push(
            "conformant-unused-v1-evaluation",
            "A signed evaluation.v1 that no selection uses sits on the record: S3 judges only the evaluations selections use, so the tier is still met.",
            s.log.receipt(&CORE_AND_SIGNED),
        );
    }

    // --- one rejecting case per clause --------------------------------------
    {
        // S0: the baseline is not met (thresholds missing), everything else
        // in place.
        let mut rules = signed_rules();
        rules.evidence_thresholds.clear();
        let mut s = story_until_claim(rules, &ALL_SIGNERS, SCHEMA_EVALUATION_ATTESTED);
        s.log.select("agent", s.c0, vec![s.e1, s.e2]);
        push(
            "baseline-not-met-fails-s0",
            "Signed, pinned, attested, but the rules carry no evidence thresholds: the baseline fails B3, so S0 fails. The signed tier stands on the baseline.",
            s.log.receipt(&CORE_AND_SIGNED),
        );
    }
    {
        // S1: signatures required only for some evolution kinds.
        let mut rules = signed_rules();
        rules.signature_required_kinds.remove(&Kind::Retraction);
        rules.signature_required_kinds.remove(&Kind::Requirement);
        let mut s = story_until_claim(rules, &ALL_SIGNERS, SCHEMA_EVALUATION_ATTESTED);
        s.log.select("agent", s.c0, vec![s.e1, s.e2]);
        push(
            "signature-not-required-for-every-kind-fails-s1",
            "Every record is signed and every author pinned, but the rules do not require signatures on Retraction and Requirement: a later unsigned record of those kinds by an unpinned actor would be accepted, so S1 fails. The tier judges the rule shape, not this log's luck.",
            s.log.receipt(&CORE_AND_SIGNED),
        );
    }
    {
        // S2: the producer signs, but its key is not pinned - an unlisted
        // actor may sign with any key, so nothing binds "agent" to a key.
        let mut rules = signed_rules();
        rules.author_keys.remove("agent");
        let mut s = story_until_claim(rules, &ALL_SIGNERS, SCHEMA_EVALUATION_ATTESTED);
        s.log.select("agent", s.c0, vec![s.e1, s.e2]);
        push(
            "unpinned-author-fails-s2",
            "The producer signs its Requirement, Candidate, and Selection, but author_keys does not pin its key: the signatures verify against whatever key they carry and bind nothing to the identity. S2 names the unpinned author and the kinds it wrote.",
            s.log.receipt(&CORE_AND_SIGNED),
        );
    }
    {
        // S3: the claim rests on signed but unattested (v2) evaluations.
        let mut s = story_until_claim(signed_rules(), &ALL_SIGNERS, SCHEMA_EVALUATION_V2);
        s.log.select("agent", s.c0, vec![s.e1, s.e2]);
        push(
            "claim-uses-unattested-evaluation-fails-s3",
            "The evaluations the claim uses are signed by a pinned evaluator but carry bellbook.evaluation.v2, whose base class is Reported: a signature never promotes a class, the schema does. S3 fails and names them.",
            s.log.receipt(&CORE_AND_SIGNED),
        );
    }
    {
        // S3 again, with the frozen v1 shape.
        let mut s = story_until_claim(signed_rules(), &ALL_SIGNERS, SCHEMA_EVALUATION_ATTESTED);
        let v1 = s.log.evaluate_v1("evaluator", s.c0);
        s.log.select("agent", s.c0, vec![s.e1, v1]);
        push(
            "claim-uses-v1-evaluation-fails-s3",
            "The claim uses a signed evaluation.v1 beside an attested one: one of two used evaluations is not attested, so S3 fails.",
            s.log.receipt(&CORE_AND_SIGNED),
        );
    }

    // --- declarations and invalidity -----------------------------------------
    {
        // A declaration naming a hash that is not this profile's table.
        let mut receipt = honest_story().log.receipt(&[BELLBOOK_CORE_V1]);
        receipt.profiles.push(ProfileRef {
            id: BELLBOOK_CORE_SIGNED_V1.into(),
            version: 1,
            hash: [0xABu8; 32],
        });
        push(
            "declared-stale-hash",
            "The honest signed story declaring bellbook-core-signed-v1 with a hash that is not the published table's: the tier is evaluated from this validator's own table and conforms, but the declaration does not match, so the profile is not met.",
            receipt,
        );
    }
    {
        // An attacker strips a signature after export: the id no longer
        // matches, the receipt is Invalid, and every clause fails.
        let mut receipt = honest_story().log.receipt(&CORE_AND_SIGNED);
        let cand = receipt
            .records
            .iter_mut()
            .find(|r| r.kind == Kind::Candidate)
            .unwrap();
        cand.author.signature = None;
        push(
            "invalid-receipt-fails-all",
            "The honest signed story with the Candidate's signature stripped after export: the record's id no longer matches its content, the receipt is Invalid, and both declared profiles fail every clause.",
            receipt,
        );
    }

    cases
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("spec")
        .join("profiles")
        .join(BELLBOOK_CORE_SIGNED_V1)
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
fn signed_vectors() {
    let table = signed_v1_table();
    let file = CasesFile {
        profile: BELLBOOK_CORE_SIGNED_V1.into(),
        hash: profile_hash(&table),
        description: "bellbook-core-signed-v1 profile vectors: each receipt paired with its validation status and every profile result validation reports for it (declared profiles in declaration order, then bellbook-core-signed-v1 where not declared); the tier met in each honest shape, one rejecting case per clause S0-S3, a stale declaration, and an Invalid receipt. Records by pinned authors carry real Ed25519 signatures.".into(),
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
    let mut statuses: Vec<ValidationStatus> = Vec::new();
    let mut failing = std::collections::BTreeSet::new();
    let mut mismatch_seen = false;
    for c in &stored.cases {
        let report = report_for(&c.receipt);
        assert_eq!(report.status, c.expect.status, "case {}", c.name);
        let got: Vec<ProfileExpect> = report.profiles.iter().map(surface).collect();
        assert_eq!(got, c.expect.profiles, "case {}", c.name);
        let p = report
            .profiles
            .iter()
            .find(|p| p.id == BELLBOOK_CORE_SIGNED_V1)
            .unwrap_or_else(|| panic!("case {}: no signed-tier result", c.name));
        assert_eq!(p.hash, stored.hash, "case {}", c.name);
        statuses.push(report.status);
        outcomes.insert(p.status);
        failing.extend(p.clauses.iter().filter(|k| !k.passed).map(|k| k.id.clone()));
        mismatch_seen |= p.declaration_matches == Some(false);
        // Every record a pinned author wrote is signed in the stored vector:
        // the signatures are real, for an independent verifier to check.
        if report.status != ValidationStatus::Invalid {
            for r in &c.receipt.records {
                if c.receipt.rules.author_keys.contains_key(&r.author.id) {
                    assert!(
                        r.author.signature.is_some(),
                        "case {}: unsigned record by pinned author {}",
                        c.name,
                        r.author.id
                    );
                }
            }
        }
    }
    // Coverage: both profile outcomes; Clean, Tainted, and Invalid histories;
    // a rejecting vector for every clause; a declaration mismatch.
    assert!(outcomes.contains(&ProfileStatus::Conformant));
    assert!(outcomes.contains(&ProfileStatus::NonConformant));
    for st in [
        ValidationStatus::Clean,
        ValidationStatus::Tainted,
        ValidationStatus::Invalid,
    ] {
        assert!(statuses.contains(&st), "no vector with status {st:?}");
    }
    for id in ["S0", "S1", "S2", "S3"] {
        assert!(failing.contains(id), "no rejecting vector for {id}");
    }
    assert!(mismatch_seen, "no vector with a mismatched declaration");
}
