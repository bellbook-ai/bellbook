"""Independent implementation of the RFC-0002 named query set (q1-q7).

From-scratch, like the rest of this validator: no shared code path with the
Rust reference. Queries are derived from wire records plus the verdict
machinery in `bellbook_verdict` (replay, retraction, taint, standing), and
emit exactly the surface JSON shapes the reference emits, so
`query-cases.json` holds both implementations to the same read-side
contract byte for byte.

Semantics per the accepted RFC-0002: a closed, named set; deterministic;
read-only; only accepted records participate; nothing silently filtered
(nodes carry standing/tainted/retracted annotations); `selected` matches
its objective exactly; no ranking of any kind.
"""

from __future__ import annotations

from typing import Any, Optional

import bellbook_verdict as bv


class QueryContext:
    """A verified log plus the derived sets every query needs."""

    def __init__(self, records: list[dict], rules_wire: dict):
        v = bv.verify_log(records, bv.Rules(rules_wire))
        if v.result != "Accept":
            raise ValueError(f"log does not verify: {v.reason}")
        self.records = records
        self.by_id = {bv.h(r["id"]): r for r in records}
        self.accepted = bv.build_state_unchecked(records).accepted
        self.retracted = set(v.retracted)
        self.tainted = set(v.tainted)
        standing = v.standing
        self.compromised = set(standing["compromised"])
        self.unsound = set(standing["unsound"])
        self.restorations = {k: list(vs) for k, vs in standing["restorations"]}

    # --- shared helpers ----------------------------------------------------

    def node(self, rid: str) -> dict:
        r = self.by_id[rid]
        kind = r["kind"]
        if kind == "Candidate":
            standing = "compromised" if rid in self.compromised else "sound"
        elif kind == "Selection":
            standing = "unsound" if rid in self.unsound else "sound"
        else:
            standing = "n/a"
        return {
            "id": rid,
            "kind": kind,
            "standing": standing,
            "tainted": rid in self.tainted,
            "retracted": rid in self.retracted,
        }

    def _cause_targets(self, r: dict) -> list[str]:
        return [bv.h(ref["target"]) for ref in bv.refs_of(r, "Cause")]

    def _back_edges(self, r: dict) -> list[tuple[str, str]]:
        """Backward structure edges of an accepted candidate: continuation
        anchors (sorted) then parent, or derivation causes (sorted) that are
        candidates - evaluation motivation is evidence, not structure."""
        data = bv.payload(r)
        basis = data["basis"]
        edges: list[tuple[str, str]] = []
        if basis == "continuation":
            for a in sorted(self._cause_targets(r)):
                edges.append((a, "continuation-anchor"))
            if data.get("parent") is not None:
                edges.append((bv.h(data["parent"]), "parent"))
        elif basis == "derivation":
            for c in sorted(self._cause_targets(r)):
                t = self.by_id.get(c)
                if t is not None and t["kind"] == "Candidate":
                    edges.append((c, "derivation"))
        return edges

    def _require(self, rid: str, kinds: Optional[tuple[str, ...]] = None) -> dict:
        r = self.by_id.get(rid)
        if r is None:
            raise ValueError(f"record {rid} not found")
        if rid not in self.accepted:
            raise ValueError(f"record {rid} was rejected at commit")
        if kinds is not None and r["kind"] not in kinds:
            raise ValueError(f"record {rid} is not one of {kinds}")
        return r

    def _selection_evidence(self, r: dict) -> list[dict]:
        out = []
        for ref in bv.refs_of(r, "Use"):
            t = self.by_id.get(bv.h(ref["target"]))
            if t is None or t["kind"] != "Evaluation":
                continue
            data = bv.payload(t)
            outcome = data["outcome"]
            # A unit variant (v1: passed/failed; spec 0.4 adds the fail-closed
            # blocked/insufficient/stale/not_run) is its own label; the
            # struct variant is `scored`.
            if isinstance(outcome, str):
                outcome_s = outcome
            else:
                s = outcome["scored"]
                outcome_s = f"scored {s['value']}e-{s['scale']}"
            out.append(
                {
                    "node": self.node(bv.h(t["id"])),
                    "criterion": data["criterion"],
                    "outcome": outcome_s,
                }
            )
        return out

    def _accepted_of_kind(self, kind: str):
        for r in self.records:
            rid = bv.h(r["id"])
            if r["kind"] == kind and rid in self.accepted:
                yield rid, r

    # --- the named set -----------------------------------------------------

    def descent(self, rid: str) -> dict:
        rec = self._require(rid, ("Candidate",))
        line = []
        seen = {rid}
        queue = list(self._back_edges(rec))
        while queue:
            aid, via = queue.pop(0)
            if aid in seen:
                continue
            seen.add(aid)
            anc = self.by_id[aid]
            line.append({"node": self.node(aid), "via": via})
            if anc["kind"] == "Candidate":
                queue.extend(self._back_edges(anc))
        return {"target": self.node(rid), "line": line}

    def descendants(self, rid: str) -> dict:
        self._require(rid)
        out = []
        for cid, _ in self._accepted_of_kind("Candidate"):
            if cid == rid:
                continue
            if any(step["node"]["id"] == rid for step in self.descent(cid)["line"]):
                out.append(self.node(cid))
        return {"target": self.node(rid), "descendants": out}

    def siblings(self, rid: str) -> dict:
        rec = self._require(rid, ("Candidate",))
        basis = bv.payload(rec)["basis"]
        own = set(self._cause_targets(rec))
        out = []
        for cid, other in self._accepted_of_kind("Candidate"):
            if cid == rid:
                continue
            ob = bv.payload(other)["basis"]
            if basis == ob and basis in ("continuation", "derivation"):
                if set(self._cause_targets(other)) == own:
                    out.append(self.node(cid))
        return {"target": self.node(rid), "siblings": out}

    def frontier(self) -> dict:
        considered: set[str] = set()
        chosen: set[str] = set()
        for _, r in self._accepted_of_kind("Selection"):
            data = bv.payload(r)
            considered.update(bv.h(c) for c in data["considered"])
            outcome = data["outcome"]
            if isinstance(outcome, dict) and "selected" in outcome:
                chosen.update(bv.h(c) for c in outcome["selected"]["candidates"])
        continued: set[str] = set()
        for _, r in self._accepted_of_kind("Candidate"):
            data = bv.payload(r)
            if data["basis"] == "continuation" and data.get("parent") is not None:
                continued.add(bv.h(data["parent"]))

        frontier = []
        for cid, _ in self._accepted_of_kind("Candidate"):
            if cid not in considered:
                reason = "unconsidered"
            elif cid in chosen and cid not in continued:
                reason = "selected-no-continuation"
            else:
                continue
            frontier.append({"node": self.node(cid), "reason": reason})
        return {"frontier": frontier}

    def standing(self, rid: str) -> dict:
        self._require(rid)
        return {
            "node": self.node(rid),
            "restorations": sorted(self.restorations.get(rid, [])),
        }

    def evidence(self, rid: str) -> dict:
        rec = self._require(rid, ("Candidate", "Selection"))
        if rec["kind"] == "Selection":
            rests_on = [
                {"selection": self.node(rid), "evidence": self._selection_evidence(rec)}
            ]
        else:
            rests_on = []
            for step in self.descent(rid)["line"]:
                if step["node"]["kind"] == "Selection":
                    sel = self.by_id[step["node"]["id"]]
                    rests_on.append(
                        {
                            "selection": step["node"],
                            "evidence": self._selection_evidence(sel),
                        }
                    )
        return {"target": self.node(rid), "rests_on": rests_on}

    def selected(self, objective: str) -> dict:
        selections = []
        for sid, r in self._accepted_of_kind("Selection"):
            data = bv.payload(r)
            if data["objective"] != objective:
                continue
            outcome = data["outcome"]
            if not (isinstance(outcome, dict) and "selected" in outcome):
                continue
            chosen = [
                self.node(bv.h(c))
                for c in outcome["selected"]["candidates"]
                if bv.h(c) in self.by_id
            ]
            selections.append(
                {
                    "selection": self.node(sid),
                    "chosen": chosen,
                    "evidence": self._selection_evidence(r),
                }
            )
        return {"objective": objective, "selections": selections}


def run_query(ctx: QueryContext, query: str, args: dict[str, Any]) -> dict:
    """Dispatch one named query by its corpus vector name and args."""
    if query == "descent":
        return ctx.descent(args["id"])
    if query == "descendants":
        return ctx.descendants(args["id"])
    if query == "siblings":
        return ctx.siblings(args["id"])
    if query == "frontier":
        return ctx.frontier()
    if query == "standing":
        return ctx.standing(args["id"])
    if query == "evidence":
        return ctx.evidence(args["id"])
    if query == "selected":
        return ctx.selected(args["objective"])
    raise ValueError(f"unknown query {query!r}")
