# Security policy

Bellbook is a tamper-evidence library; soundness of its verification is the
product. Reports that break the integrity story are treated as security
issues, not ordinary bugs - for example:

- forging a record or verdict that `verify_log` accepts,
- producing two different records with the same id (canonicalization or
  hashing collisions in practice),
- bypassing capability/approval rules in `verify_record`,
- corrupting the log through the commit/recovery protocol without detection,
- removing or substituting a completed record signature without changing its
  record id or anchored head.

## Reporting a vulnerability

Please do not open a public issue for suspected vulnerabilities. Use
GitHub's private vulnerability reporting on this repository ("Report a
vulnerability" under the Security tab), or email
[contact@bellbook.ai](mailto:contact@bellbook.ai). You will get an
acknowledgement within a week.

## Confidentiality and data minimization

Bellbook provides **integrity, not confidentiality**. Records and
receipts carry full payloads in the clear - prompts, responses, action
parameters, tool output - and hashing does not hide any of it. A receipt
inherits the sensitivity of everything committed to the log; sharing one
is disclosure. Never place credentials, tokens, or secrets in record
payloads; redact or minimize sensitive content before committing;
encryption, access control, and retention are host responsibilities.
Selective disclosure is tracked as future work (see the issues).

## Known, documented limitations

SPEC.md §11 (threat model) and §13 (known limitations) state what is
by-design for this version - for example: tamper-evidence detects interior
edits but does not stop the ledger's owner rewriting history from genesis
(mitigate by anchoring the head attestation externally, SPEC §11.1);
author identity is cryptographically bound only for actors with pinned
signing keys; logs and receipts assume in-memory scale, with validation
resource-bounded by default (`ValidationLimits`, CLI `--max-size`).
Reports within those documented bounds are welcome as regular issues.

## Hardening

**Fuzzing.** The receipt trust boundary - the surface that takes untrusted
bytes: `validate`, `Receipt::from_bytes`, and `canonical_json` - is fuzzed at
two levels (issue #65):

- A fast, deterministic, seeded harness runs in the ordinary test suite on
  every push (`tests/fuzz_trust_boundary.rs`). It asserts the invariants that
  must hold for *any* input: `validate` never panics, a Clean report lists
  nothing retracted or tainted, an Invalid report always states a reason, and
  RFC 8785 canonicalization is total and idempotent.
- A coverage-guided libFuzzer target set (`fuzz/`, run weekly and on demand via
  `.github/workflows/fuzz.yml`) explores the same entry points more deeply. A
  crash or a violated invariant there is a security finding, reported as above.

**Security review, and what 1.0 ships on.** 1.0 does not ship on an external
security review, and its release notes say so: nothing outside the project
depends on Bellbook enough yet to justify funding one, and Bellbook does not
claim assurance it has not earned. What gates 1.0 instead (RFC-0003 decision
10, issue #114):

1. an internal adversarial review of the trust boundary above, published in
   this repository with every finding and its resolution
   ([docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md), re-dated at the
   release commit);
2. the coverage-guided fuzz targets clean over a stated budget on the release
   commit, with every earlier finding kept as a regression seed in the
   per-push harness;
3. zero unresolved findings of any severity from either.

The external review stays open in issue #75 and is commissioned when an
adopter's dependence justifies it; its acceptance gate is **zero unresolved
blocker-severity findings**, and its findings will be published.
