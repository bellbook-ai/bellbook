"""An independent, validation-only reimplementation of Bellbook's wire format.

This is a *from-scratch* Python implementation - it does NOT wrap, link, or call
the Rust crate. Its purpose (issue #5) is to independently confirm the parts of
the v0.2 specification that must be identical across implementations:

  * RFC 8785 (JCS) canonicalization of records,
  * SHA-256 content-addressed record ids,
  * the head hash and rules hash,
  * strict wire decoding (unknown fields reject),
  * structural log integrity (genesis time, gap-free time, id chain,
    subject/verdict pairing).

It deliberately does NOT re-derive verdicts (the full per-record rule battery and
the retraction/taint state machine). That larger layer is the next increment; see
the README. Everything here is checked against `spec/test-vectors-v0.2.json` and
`spec/conformance/v0.2/` by `run_conformance.py`.

Only the Python standard library is required for canonicalization, ids, and
structure. Ed25519 signature verification (used only for the signed test vector)
uses the `cryptography` package if present and is skipped with a clear notice
otherwise.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

SPEC_VERSION = "0.2"
SIGNING_DOMAIN = "bellbook.record-signature.v0.2"
# 2**53 - 1: the I-JSON safe-integer range JCS numbers must stay within,
# matching `MAX_SAFE_INTEGER` in the reference's canonical.rs.
MAX_SAFE_INTEGER = 9_007_199_254_740_991

# The exact, ordered field set of each wire object. Decoding rejects any object
# that is missing a field or carries an unknown one - the Python mirror of
# serde's `deny_unknown_fields`.
RECORD_FIELDS = frozenset(
    {"id", "space", "thread", "time", "author", "kind", "schema", "data", "refs", "evidence"}
)
AUTHOR_FIELDS = frozenset({"id", "type", "signature"})
AUTHOR_REQUIRED = frozenset({"id", "type"})
SIGNATURE_FIELDS = frozenset({"key_id", "sig"})
REF_FIELDS = frozenset({"type", "target"})
RECEIPT_FIELDS = frozenset({"spec_version", "rules", "records"})


class DecodeError(Exception):
    """A strict-decoding failure (the Python analogue of a structural reject)."""


# ---------------------------------------------------------------------------
# RFC 8785 (JCS) canonicalization
# ---------------------------------------------------------------------------


def jcs(value: Any) -> str:
    """Return the RFC 8785 canonical JSON text for `value`.

    Bellbook records contain only objects, arrays, strings, booleans, null, and
    non-negative integers (byte arrays are arrays of 0..=255, times/turns are
    unsigned ints), so the general JCS number rules never engage. Object keys
    are ASCII, so code-point sort order equals JCS's UTF-16 order. Strings use
    JSON's minimal escaping, which `json.dumps(..., ensure_ascii=False)`
    produces. A float would be a spec violation and is rejected here rather than
    silently formatted.
    """
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, bool):  # pragma: no cover - covered by the two lines above
        return "true" if value else "false"
    if isinstance(value, int):
        if value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
            raise DecodeError(f"integer {value} exceeds the I-JSON safe range required by JCS")
        return str(value)
    if isinstance(value, float):
        raise DecodeError("floating-point numbers are not part of the v0.2 wire format")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + jcs(v)
                for k, v in sorted(value.items())
            )
            + "}"
        )
    raise DecodeError(f"value of type {type(value).__name__} is not JSON")


def canonical_bytes(value: Any) -> bytes:
    return jcs(value).encode("utf-8")


# ---------------------------------------------------------------------------
# Hashes and ids
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def bytes32(field: Any) -> bytes:
    """Interpret a wire 32-byte value (a JSON array of 32 ints) as bytes."""
    if not isinstance(field, list) or len(field) != 32 or any(
        not isinstance(b, int) or b < 0 or b > 255 for b in field
    ):
        raise DecodeError("expected a 32-byte array")
    return bytes(field)


def record_id(record: dict) -> bytes:
    """The canonical id form omits `id` and, matching the reference's
    `skip_serializing_if = "Option::is_none"`, drops `author.signature` when it
    is null (a present signature is kept and bound into the id). Everything else
    is kept, then SHA-256 hashes the canonical bytes."""
    form = {k: v for k, v in record.items() if k != "id"}
    author = {k: v for k, v in form["author"].items() if not (k == "signature" and v is None)}
    form = {**form, "author": author}
    return sha256(canonical_bytes(form))


def signing_bytes(record: dict) -> bytes:
    """The signing form omits `id` AND `author.signature`, then wraps the
    canonical record with the version-specific signing domain."""
    form = {k: v for k, v in record.items() if k != "id"}
    author = dict(form["author"])
    author.pop("signature", None)
    form = dict(form)
    form["author"] = author
    inner = {"domain": SIGNING_DOMAIN, "record": form}
    return canonical_bytes(inner)


def head_hash(records: list[dict]) -> bytes:
    """SHA-256 over the concatenation of every record's 32-byte id."""
    joined = b"".join(bytes32(r["id"]) for r in records)
    return sha256(joined)


def rules_hash(rules: dict) -> bytes:
    """SHA-256 of the canonical form of the rules object exactly as it appears
    on the wire (the crate's `sha256_canonical(rules)`)."""
    return sha256(canonical_bytes(rules))


# ---------------------------------------------------------------------------
# Strict wire decoding
# ---------------------------------------------------------------------------


def _require_exact_object(obj: Any, allowed: frozenset, required: frozenset, what: str) -> dict:
    if not isinstance(obj, dict):
        raise DecodeError(f"{what} must be a JSON object")
    keys = set(obj.keys())
    unknown = keys - allowed
    if unknown:
        raise DecodeError(f"unknown field `{sorted(unknown)[0]}` in {what}")
    missing = required - keys
    if missing:
        raise DecodeError(f"missing field `{sorted(missing)[0]}` in {what}")
    return obj


def _is_int(v: Any) -> bool:
    # bool is a subclass of int in Python; a JSON boolean is not an integer.
    return isinstance(v, int) and not isinstance(v, bool)


def decode_record(obj: Any) -> dict:
    rec = _require_exact_object(obj, RECORD_FIELDS, RECORD_FIELDS, "record")
    author = _require_exact_object(rec["author"], AUTHOR_FIELDS, AUTHOR_REQUIRED, "author")
    if not isinstance(author["id"], str):
        raise DecodeError("author id must be a string")
    if not isinstance(author["type"], str):
        raise DecodeError("author type must be a string")
    if author.get("signature") is not None:
        _require_exact_object(author["signature"], SIGNATURE_FIELDS, SIGNATURE_FIELDS, "signature")
    if not _is_int(rec["time"]):
        raise DecodeError("time must be an integer")
    if not isinstance(rec["kind"], str):
        raise DecodeError("kind must be a string")
    if not isinstance(rec["evidence"], str):
        raise DecodeError("evidence must be a string")
    if not isinstance(rec["refs"], list):
        raise DecodeError("refs must be an array")
    for ref in rec["refs"]:
        ref = _require_exact_object(ref, REF_FIELDS, REF_FIELDS, "ref")
        if not isinstance(ref["type"], str):
            raise DecodeError("ref type must be a string")
        bytes32(ref["target"])
    # Validate 32-byte shapes so a malformed id/space/etc. rejects.
    for f in ("id", "space", "thread", "schema"):
        bytes32(rec[f])
    if not isinstance(rec["data"], list) or any(
        not _is_int(b) or b < 0 or b > 255 for b in rec["data"]
    ):
        raise DecodeError("data must be an array of bytes 0..=255")
    return rec


def decode_receipt(text: str) -> dict:
    """Strictly decode a receipt document. Raises DecodeError on any structural
    problem (unparseable JSON, unknown/missing fields, wrong spec version)."""
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise DecodeError(f"unparseable receipt: {e}") from e
    receipt = _require_exact_object(obj, RECEIPT_FIELDS, RECEIPT_FIELDS, "receipt")
    if receipt["spec_version"] != SPEC_VERSION:
        raise DecodeError(
            f"unsupported spec version {receipt['spec_version']!r} "
            f"(this validator implements {SPEC_VERSION!r})"
        )
    if not isinstance(receipt["records"], list):
        raise DecodeError("records must be an array")
    for r in receipt["records"]:
        decode_record(r)
    return receipt


# ---------------------------------------------------------------------------
# Structural log integrity (no verdict re-derivation)
# ---------------------------------------------------------------------------


class StructuralResult:
    """Outcome of the structural layer: `ok` is False when the log fails a
    structural rule, with `problem` naming the first failure."""

    def __init__(self, ok: bool, problem: str | None):
        self.ok = ok
        self.problem = problem

    def __repr__(self) -> str:
        return f"StructuralResult(ok={self.ok}, problem={self.problem!r})"


def check_structure(records: list[dict]) -> StructuralResult:
    """Independently verify the structural invariants replay enforces before any
    verdict is re-derived, in the reference's order (replay.rs): gap-free time
    from a genesis of 1, then recomputed ids, then subject/verdict pairing (each
    non-verdict immediately followed by a Verdict whose single Cause ref names
    it). Returns the first failure, if any."""
    if not records:
        return StructuralResult(True, None)

    # 1. Genesis time is 1; time is gap-free and strictly +1 per record.
    if records[0]["time"] != 1:
        return StructuralResult(False, "genesis record time is not 1")
    for i in range(1, len(records)):
        if records[i]["time"] != records[i - 1]["time"] + 1:
            return StructuralResult(False, "logical time is not gap-free")

    # 2. Every stored id equals its independent recomputation.
    for r in records:
        if record_id(r) != bytes32(r["id"]):
            return StructuralResult(False, "record id does not match recomputation")

    # 3. Subject/verdict pairing: walk the log in pairs.
    i = 0
    n = len(records)
    while i < n:
        rec = records[i]
        if rec["kind"] == "Verdict":
            return StructuralResult(False, "verdict record without a preceding subject")
        if i + 1 >= n:
            return StructuralResult(False, "final subject record has no verdict")
        nxt = records[i + 1]
        if nxt["kind"] != "Verdict":
            return StructuralResult(False, "subject record is not followed by a verdict")
        cause = [ref for ref in nxt["refs"] if ref["type"] == "Cause"]
        if len(cause) != 1 or bytes32(cause[0]["target"]) != bytes32(rec["id"]):
            return StructuralResult(False, "verdict does not name its subject via a single Cause ref")
        i += 2
    return StructuralResult(True, None)


def validate(text: str, max_bytes: int | None = None, max_records: int | None = None):
    """Structural validation of a receipt document, in the order the crate uses:
    byte budget, then strict decode, then record budget, then structural
    integrity. Returns ("Invalid", problem) on any failure, or
    ("StructurallyValid", None). This is NOT the full status - deciding Clean vs
    Tainted requires verdict re-derivation, which this increment does not do -
    but it agrees with the reference validator on every rejection it can reach.
    Any unexpected shape in hostile input becomes a clean Invalid, never a
    traceback."""
    if max_bytes is not None and len(text.encode("utf-8")) > max_bytes:
        return ("Invalid", "receipt exceeds size limit")
    try:
        receipt = decode_receipt(text)
        if max_records is not None and len(receipt["records"]) > max_records:
            return ("Invalid", "receipt exceeds record limit")
        res = check_structure(receipt["records"])
    except DecodeError as e:
        return ("Invalid", str(e))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:  # noqa: BLE001 - untrusted input must not traceback
        return ("Invalid", f"malformed receipt: {e}")
    if not res.ok:
        return ("Invalid", res.problem)
    return ("StructurallyValid", None)
