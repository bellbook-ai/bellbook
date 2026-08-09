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
