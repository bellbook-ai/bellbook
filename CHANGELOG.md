# Changelog

All notable changes to Bellbook are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Machine-readable conformance corpus under `spec/conformance/v0.2/`
  (record, receipt, and malformed-document cases) with a runner that
  re-derives every outcome from the stored inputs. It triggers a case for
  every verdict rejection reason the portable format can express and
  documents the three reason codes it cannot. Regenerate with
  `UPDATE_CONFORMANCE=1`.
- Independent, from-scratch Python validator under `conformance/python/`
  (not a binding over the Rust core) that reproduces the test vectors and
  the conformance corpus, confirming cross-implementation agreement on
  canonicalization, record ids, head/rules hashes, strict decoding, and
  structural log integrity. Runs in CI.
- Independent Python verdict engine (`conformance/python/bellbook_verdict.py`)
  that re-derives every conformance-corpus verdict and replays every receipt
  to the same status, reason, and retracted/tainted sets: the full per-record
  rule battery, the retraction and transitive-taint state machine, and
  whole-log replay. Completes the cross-implementation check of Bellbook's
  verification policy, not just its hashing.

## [0.2.0] - 2026-08-09

First public release. Implements Bellbook spec version 0.2, the first
published compatibility epoch.

### Added

- Twelve typed record kinds covering requests, actions, responses, results,
  authority, approvals, refusals, plans, usage, summaries, retractions, and
  deterministic verdicts.
- RFC 8785 JSON canonicalization and SHA-256 content-addressed record ids.
- Typed `Cause`, `Use`, `Require`, and `Replace` references between records.
- Deterministic record and full-log verification with gap-free logical time,
  subject/verdict pairing, verdict re-derivation, author-role enforcement,
  request lifecycle checks, and authority resolution.
- Five evidence classes with weakest-link derivation and configurable
  per-record-kind thresholds.
- Strict Ed25519 record signatures with actor key pinning and a
  version-specific signing domain.
- Append-only retractions with transitive taint through epistemic
  dependencies.
- A crash-safe, exclusively locked file writer with verified open, bounded
  loading, pair-atomic commits, recovery, deterministic batches, and
  idempotent compare-and-append.
- Portable receipts and the `bellbook validate` CLI for bounded offline
  validation from genesis.
- Trusted checkpoints for host-side replay acceleration and canonical head
  attestations for external anchoring.
- Deterministic context selection and verified state construction.
- Versioned canonical test vectors, including signed-record vectors.
- CI across Linux, macOS, and Windows, Rust 1.75 compatibility checks,
  documentation checks, scheduled RustSec scanning, and Dependabot updates.

### Security

- Record ids bind completed signatures; removing or substituting a signature
  changes the record id and every dependent reference or anchored head.
- Signature input is domain-separated as
  `bellbook.record-signature.v0.2`, preventing cross-protocol and
  cross-version replay.
- Receipt, rule, record, author, signature, reference, and payload decoding is
  strict: unknown fields, duplicate logical keys, and non-canonical payloads
  reject.
- Receipt and persistent-log input is resource-bounded before verification or
  unbounded allocation.
- Replay recomputes record ids and stored verdicts, including complete verdict
  envelope validation.
- Checkpoints cannot arrive through receipts and are accepted only through the
  explicit trusted-checkpoint API.
- Persistent commits reserve and recover the complete subject/verdict pair;
  uncertain durable writes require reopen and recovery before another commit.
- Key-pinned actors must sign every record, and actor identities are bound to
  configured roles.
- Actions name the exact capability and approval that authorized them;
  retracted authority no longer authorizes later actions.

### Known limitations

- Bellbook proves consistency of captured activity, not capture completeness.
- Bellbook provides integrity, not confidentiality; records and receipts may
  contain sensitive payloads.
- A storage owner can replace an unanchored log from genesis. Key-pinned
  signatures and externally stored head attestations limit that threat.
- Receipt status is evaluated under the embedded verifier rules. Consumers
  compare `rules_hash` against rules they trust.

See [SPEC.md](SPEC.md) for normative behavior and [SECURITY.md](SECURITY.md)
for the security model and vulnerability-reporting process.
