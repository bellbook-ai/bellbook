# Bellbook and the surrounding ecosystem

Bellbook is deliberately one layer of a larger stack: the **evidence
plane**. It does not establish identities, evaluate policies, or
transport telemetry; it preserves portable, independently replayable
proof of what was requested, what authority existed, what was decided,
what was attempted, and what came back.

The categories below matter more than the named instances: the examples
are real products and standards (verified as of August 2026) but the
list is not exhaustive, and Bellbook's positioning does not depend on
any of them existing tomorrow.

| Layer | Examples | Bellbook relationship |
|-------|----------|-----------------------|
| Identity and lifecycle | [SailPoint Agentic Fabric](https://www.sailpoint.com/products/agentic-fabric), [Okta for AI Agents](https://www.okta.com/products/okta-for-ai-agents/), [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id), [CyberArk Secure AI Agents](https://www.cyberark.com/products/secure-ai-agents/), cloud IAM | Supplies identities, owners, and entitlements that Bellbook records as authors, capabilities, and approvals |
| Runtime authorization | [Dogwood](https://github.com/dogwood-policy/dogwood) (an open-source temporal policy language extending Cedar), [Cedar](https://www.cedarpolicy.com/), [OPA](https://www.openpolicyagent.org/), [Amazon Bedrock AgentCore](https://aws.amazon.com/bedrock/agentcore/) Policy | Supplies permit/deny decisions that Bellbook can capture as evidence (planned `PolicyDecision` record) |
| Telemetry | [OpenTelemetry](https://opentelemetry.io/), [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) | Supplies captured execution events; a transport, while Bellbook is the system of record |
| Provenance and supply chain | [W3C PROV](https://www.w3.org/TR/prov-overview/), [in-toto](https://in-toto.io/), [SCITT](https://datatracker.ietf.org/wg/scitt/about/), [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) | Standards and transparency services Bellbook can export receipts into or anchor head attestations against |
| Verifiable evidence | Bellbook | Produces independently replayable receipts |

These are primary-layer classifications, not exclusive product boundaries.
Some systems span several layers: for example, SailPoint Agentic Fabric also
describes runtime policy enforcement when agents invoke tools. That overlap
does not change Bellbook's role as the portable evidence plane around those
identity and enforcement decisions.

The agent-identity layer is crowded and moving fast (several of the
products above reached general availability within the last year);
Bellbook treats all of them the same way: stable actor ids in,
capabilities/approvals recorded, receipts out.

## Integration status labels

Every integration reference in this repository uses exactly one of
these labels, and the label states what actually exists:

- **Conceptual mapping**: documentation only. No code.
- **Reference adapter**: working example code exists in this repository.
- **Tested integration**: CI exercises the external system.

As of this writing, **every named third-party system above is a
conceptual mapping**. There are no adapters and no tested integrations
yet. The planned first reference adapter targets an open-source runtime
authorization engine (tracked in the issues) because open-source engines
can be exercised in CI; [Dogwood](https://github.com/dogwood-policy/dogwood)
is the current candidate, noting that its repository positions the
reference interpreter for exploration and testing rather than
production, and that it returns policy decisions without logging them.
The purpose of an adapter would be portable signed capture and independent
replay across systems, not merely duplicating a runtime log. Proprietary
platforms get adapters only when a test environment, stable identifiers,
and automated contract tests are available.

## Conceptual mapping sketches

Runtime authorization (a policy engine gating agent tool calls): an
agent tool-call proposal maps to an `Action`; the engine's permit/deny
maps to the planned `PolicyDecision` record; the tool response maps to
a `Result` (or a failed `Result`); a gateway denial maps to a `Refusal`;
prior human authorization maps to an `Approval`; a deployed entitlement
maps to a `Capability`; the evaluated policy bundle is referenced by
hash from the decision.

Identity and lifecycle (an enterprise agent-identity platform): an
agent identity maps to a stable, URI-shaped Bellbook `author.id`
(e.g. `urn:vendor:agent:<tenant>:<identity-id>`, hashing or omitting
tenant-sensitive identifiers in public receipts); an entitlement or
access grant maps to a signed `Capability`; a just-in-time approval
maps to an `Approval`; a revocation maps to a `Retraction` or a
replacing deny-mode capability; an access decision maps to the planned
`PolicyDecision`; agent execution maps to `Action` and `Result`.

## Trademarks

Product and project names referenced here belong to their respective
owners. References describe conceptual relationships only and do not
imply endorsement, compatibility claims, or certification by any vendor.
