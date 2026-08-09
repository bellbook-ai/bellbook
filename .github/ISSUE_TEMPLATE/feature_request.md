---
name: Feature request
about: Propose an addition or change
labels: enhancement
---

## Problem

What can't you do today, or what is harder than it should be?

## Proposal

What you'd like to see. For anything touching the record format, the
verifier rules, or receipt semantics, note that changes are gated by the
spec (SPEC.md is normative) and by the backward-validity guarantee
(SPEC section 14).

## Alternatives considered

Other approaches and why they fall short.

## Scope check

Bellbook is deliberately small: not a logger, not a database, not a
runtime, not a service. Features outside the evidence-kernel scope are
usually better as host-side layers; see README "Status & roadmap".
