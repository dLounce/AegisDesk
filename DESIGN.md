# AegisDesk — Design

> **Status: early development.** This document records the design the implementation is
> being built against. Sections describing components that do not exist yet are marked
> *Planned*. Nothing here should be read as a description of shipped behaviour unless it is
> marked *Implemented*.

---

## 1. Design goal

Give an agentic system enough autonomy to be useful on real IT work, while ensuring that a
model which is wrong, manipulated, or overconfident cannot turn that state into operational
authority.

The system is therefore split into two halves with different trust properties:

- a **reasoning half** — agents that classify, clarify, troubleshoot, and propose actions;
- a **decision half** — deterministic code and authoritative state that decides what may
  actually execute.

The reasoning half is treated as untrusted. It is useful, not authoritative.

## 2. Trust boundaries

| Boundary | Trusted side | Untrusted side |
| --- | --- | --- |
| Session → workflow | Authenticated employee identity from the session layer | Any identity claim appearing in message text |
| Agent → runtime guard | Capability registry, policy engine, backend state | Tool name and arguments proposed by a model |
| Store → resume | Approval record read back from the store | The interrupt resume payload |
| Backend → tool | Server-side authorization on every call | The claim that a call was already authorized |
| Knowledge base → agent | Document contents as *data* | Document contents as *instructions* |

Everything the model can influence is on the untrusted side of at least one boundary.

## 3. Architectural decisions

### AD-1 — The protected-action gate lives inside the tool implementation

A gate implemented as a workflow node is reachable only if the workflow routes to it, and
routing is influenced by model output. Placing the gate as the first thing the protected
tool does makes it unskippable regardless of graph topology or agent behaviour.

*Status: implemented.* `RuntimeGuard.propose` is the single path to a protected operation
and is called from inside the protected tool. The workflow that will call it does not exist
yet, so the placement is enforced by the code that exists rather than demonstrated end to end.

### AD-2 — Trusted identity travels in runtime context, not workflow state

Workflow state is written by nodes and therefore sits adjacent to model output. The
authenticated session context is supplied by the API layer on every invocation and resume,
is immutable for the run, and has no path from message text. Cross-employee action is not
merely denied; the protected tool's argument schema has no field in which another
employee could be named.

*Status: partially implemented.* The typed session record and the boundary that produces it
are in place; the runtime context that carries them through a workflow, and the protected
tool whose schema omits an employee field, are not built yet.

### AD-3 — Approval binds to a digest of the exact arguments

Binding an approval to an action identifier alone would allow arguments to change between
approval and execution. The approval record stores a digest of the canonical argument set;
resume recomputes it and fails closed on any mismatch.

*Status: partially implemented.* The digest is computed and carried on every resolved
proposal; the approval record that binds to it lands with the approval store.

### AD-4 — Action identifiers are derived deterministically

Code containing a workflow pause re-executes when the workflow resumes. A randomly
generated identifier would differ between the proposing pass and the resuming pass and
would silently break approval binding. Identifiers are derived from stable workflow inputs.

*Status: implemented.* `derive_action_id` hashes the canonical form of the resolved action,
so the proposing pass and a resuming pass agree without persisting a generated value.

### AD-5 — No non-idempotent side effect before the pause

A direct consequence of AD-4. Proposal persistence and the corresponding audit write are
idempotent upserts, so a second pass over the same code is a no-op rather than a
duplicate.

*Status: partially implemented.* The path from proposal to decision performs reads only and
returns identical values when run twice. Proposal persistence and the audit write do not
exist yet, so the idempotency they require is a stated rule rather than shipped behaviour.

### AD-6 — Agents may propose privileged actions; they may not execute them

Capability sets distinguish proposing from executing. No agent holds execute authority for
protected operations. Execution authority belongs to the runtime, and only after an
authoritative approval has been read back from the store.

*Status: partially implemented.* Capability sets distinguish proposing from executing, and
no agent holds execute authority. Execution after an authoritative approval lands with the
approval store; until then an effect other than ALLOW is refused.

### AD-7 — Classification runs on every inbound message

Re-classifying each turn means a conversation that changes scope mid-way — a routine
troubleshooting thread that turns into a privileged access request — is caught
structurally, without a special-purpose detector, and without the workflow inheriting the
risk tier it started with.

*Status: deferred to the agent milestone.* Re-classification needs a classifier and a turn,
neither of which exists. Building the limit records now would leave infrastructure nothing
consumes.

### AD-8 — An explicit bounded tool loop rather than a prebuilt agent runtime

An explicit loop keeps per-agent capability binding, turn and handoff limits, and
trajectory logging visible in the codebase, which the evaluation work depends on. It also
avoids a deprecated framework entry point and the dependency it would pull in.

*Status: deferred to the agent milestone.* For the same reason as AD-7: a bounded loop needs
a loop.

### AD-27 — Baseline access is directory state, not session state and not engine logic

Baseline access is keyed by employee *and* resource, so a session record cannot hold it: a
session is established before any resource is named. Deriving it from role or department
would put a company policy value into code, which the policy engine already declines to do.
It is therefore stored as an explicit grant per employee and resource, read back through the
directory under the same self-scoping as any other employee record, and handed to the policy
engine as a trusted input. Absence is reported rather than defaulted, and policy treats
absence as no automatic access, so an unrecorded pair escalates instead of resolving.

*Status: implemented.*

### AD-28 — Risk tier arrives from a trusted producer, and the session is not it

The tier is a property of a proposed action, not of the person asking, so it does not belong
on a session record. Classification is a Router responsibility and the Router is a model, so
the tier reaching a decision has to be bound by the runtime guard rather than accepted from
agent output. No governing document states a mapping from anything to a tier, so none is
written here; the engine continues to record the tier without consulting it.

*Status: implemented.* The guard reads the tier from configuration keyed on the resolved
resource class, the requested permission and the requested duration. The values are seed
configuration for the fictional company; no layer of the system computes a tier, and the
engine still records it without consulting it.

### AD-29 — Session context is re-supplied on resume and compared by value

The session record is not a field on workflow state and is not read back from a checkpoint as
authoritative. The API layer supplies it on the first invocation and again on each resume,
and the resuming pass compares the value it was handed to the value the run started with. It
is frozen and closed to unknown fields so that comparison means what it appears to mean.

*Status: partially implemented.* The record and its comparison semantics exist; the
enforcement point lands with the workflow.

### AD-32 — The proposal names; the guard resolves

A proposal carries an operation, a resource identifier, a permission, a duration and a ticket.
The requester, the resource record, the baseline permission, the risk tier, the action
identifier and the argument digest are produced by the guard from the session, the catalogue,
the directory, configuration and the runtime. None of them has a field a proposal could arrive
in, so a self-built resource record, a baseline the directory never issued, or a grant to
somebody else is not expressible rather than merely refused.

Identity is checked before any of it. An object that merely carries an `employee_id` attribute
would otherwise pass every later check, because the directory scopes a read to the requester the
caller named — which is exactly the claim the session boundary exists to refuse. The guard
therefore verifies that it holds a real session record, in the same way the policy engine
verifies that it holds a real request record.

The order matters as much as the split: identity, then the shape of the proposal, then the
capability check, all before any backend read, so a caller failing any of them learns nothing
about the directory, the catalogue or the ticket store by watching what happens next.

*Status: implemented.*

### AD-33 — Identity is derived from the action; the digest additionally binds the policy version

The action identifier is a domain-separated hash of the canonical form of the resolved action:
operation, requester, resource, permission, duration, ticket and workflow. The argument digest
covers the same fields plus the identifier and the policy version in force when the decision was
reached.

Keeping the policy version out of the identifier and inside the digest is deliberate. A rule
edit between approval and execution then produces a digest mismatch that can be reported,
rather than a lookup by identifier that quietly finds nothing and is indistinguishable from a
missing approval.

Every value in a canonical form comes from an authoritative record, so no value a model chose
can carry a separator and forge a neighbouring field. Both forms are pinned by golden vectors,
so a change to the serialisation is a visible test failure rather than a silent re-binding of
approvals already issued.

*Status: implemented.*

### AD-34 — Resume fetches by derived identity and compares the semantic decision

The approval record is fetched by the workflow and action identifiers the resuming workflow
derives for itself, never by an identifier supplied in the resume payload. A payload-supplied
key would let a genuine approval for one action authorise a different one, and every subsequent
check would pass because the record itself is real.

Execution then requires that the re-evaluated policy version, effect, reason, requester,
resource, permission and duration are identical to the tuple recorded on the approval. Whole
decision records cannot be compared: the evaluation timestamp legitimately differs between the
proposing pass and the resuming one. Any difference in the semantic tuple fails closed,
including a change that would now permit the action outright, because a changed world is a
world the reviewer did not authorise.

*Status: not started.* The rule is fixed here; the approval store that applies it lands next.

### AD-35 — One refusal sentence to the model, the precise reason to the audit trail

Every refusal returns the same text. A refusal naming its cause would let a compromised agent
search the argument space by comparing replies until one combination is permitted, which is the
same oracle the directory and the session boundary already avoid. The refusal reason and the
full policy decision travel on the outcome record instead, which is bound for the audit trail
rather than for the conversation.

*Status: implemented.*

### AD-36 — The capability registry encodes stated grants only

The registry maps an agent to the capabilities the governing documents grant it, and nothing is
inferred from an agent's prose responsibilities. An unlisted capability is refused, an unlisted
agent is refused, and a protected operation with no registry entry has no capability that can
propose it. The Resolver invariant is stated negatively against the set of privileged
capabilities and checked when the module is imported, so a capability that becomes privileged
later is refused for the Resolver without anybody revisiting the registry.

One limit is worth stating plainly: because the Router chooses the route and the Router is a
model, a compromised Router can always reach Escalation and therefore the capability to propose
a grant. The Resolver and Escalation split constrains the trajectory, not the outcome. Only the
approval gate constrains the outcome.

*Status: implemented.*

### AD-37 — Protected execution requires a receipt the guard minted

The access backend accepts one argument type and has no signature taking loose identifiers, so a
grant to an employee nobody authorised cannot be spelled. The receipt class is importable, so a
caller can construct one; constructing it is therefore not what authorises anything.

Each backend instance generates a minting key at construction and issues it to the first caller
that claims minting authority — the guard, when the guard is built. A second claim is refused, so
a component that loads later cannot acquire the ability to mint by asking. Execution requires
both a receipt and that key, compared as bytes in constant time, and a receipt presented without
it is refused with the same message as a missing receipt.

What this does not cover is stated plainly rather than implied: code that can reach the guard
instance's private attribute, or that constructs its own backend, can still execute against that
backend. The key raises the bar from "import the class" to "hold the object", and the second
control — the action identifier, derived from the action itself — still refuses a duplicate
grant under an identifier that already resolved.

That combination is deterministic idempotency at one boundary. It is not a distributed
exactly-once guarantee, and no such claim is made until the backend sits behind a process
boundary with its own authorisation.

*Status: implemented.*

## 4. Pause and resume semantics

This is the most consequential runtime behaviour in the system and is treated as a hard
constraint rather than an implementation detail.

**Before the pause:** deterministic validation → capability validation → schema validation
→ policy evaluation → idempotent proposal persistence → idempotent audit write.

**After the resume:** re-fetch the authoritative approval record → verify approved status →
recompute and verify the exact argument digest → re-fetch authoritative requester and
resource state → re-run policy → execute through the backend keyed by the action identifier
→ record execution in the audit log.

Two rules follow, and neither is negotiable:

1. The resume payload is never treated as authoritative approval state.
2. No non-idempotent side effect occurs before the pause.

Rule 2 and an append-only audit trail are in tension, because the pre-pause code re-executes on
every resume. They are reconciled by making the pre-pause proposal and audit writes
insert-if-absent under the workflow identifier, action identifier and event type: append-only as
the application sees it, idempotent under replay. Counting a replay as a fresh protected-action
attempt would corrupt the security metrics and make a retry indistinguishable from an attack.

*Status: verified as achievable against the workflow runtime; not yet implemented.*

## 5. Durability

Durable approval is part of the thesis rather than an optimisation. The target property is
that the following sequence works with the workflow process terminating in the middle:

```
request → proposed privileged action → capability and policy gate
→ durable approval record → pause → process terminates
→ reviewer approves → fresh process resumes
→ authoritative approval re-read → policy re-evaluated
→ action executes exactly once → audit records the whole trajectory
```

PostgreSQL is the durable implementation for checkpoints, approvals, audit events, and
access grants. In-memory implementations of the same interfaces exist for fast tests, and
the choice is made by configuration rather than by code changes.

*Status: planned.*

## 6. Tool interfaces and MCP

Tools are defined behind clean internal interfaces. When they are exposed over MCP, the
security ordering must not change:

```
agent capability → runtime guard → policy and authorization
→ human approval where required → tool transport → backend authorization and execution
```

MCP is a transport, not a security boundary. Backend authorization stays authoritative even
if an agent or a tool client is compromised.

*Status: planned.*

## 7. Threat model

Mapped against the OWASP agentic risk categories as a reference for structuring the work,
not as a compliance claim. Every row will carry an honest status of *implemented*,
*partial*, or *out of scope* as the system is built.

| Risk | Intended control | Status |
| --- | --- | --- |
| Goal hijack via injected instructions | Untrusted-content separation; policy outside the model | Not started |
| Tool misuse | Strict argument schemas, enumerated permissions, resource catalogue | Partial |
| Identity and privilege abuse | Session-derived identity, self-scoped reads, least-privilege capabilities | Partial |
| Unexpected code execution | No arbitrary execution capability exists | Not started |
| Memory and context poisoning | Authoritative approval lookup; conversation text cannot authorize | Not started |
| Insecure inter-agent communication | Structured typed handoffs with explicit reasons | Not started |
| Cascading failures | Turn, handoff, and tool-call limits; fail-closed defaults | Not started |
| Human-agent trust exploitation | Reviewers see the raw proposed action, not a model summary | Not started |
| Rogue agent behaviour | Fixed capability sets and termination limits | Partial — capability sets exist, termination limits do not |

## 8. Testing approach

Security properties are expressed as executable tests, not as documentation. The suite is
designed to run with no live model calls: agents are driven by a scripted model that emits
exact tool calls, which makes it possible to simulate a compromised agent deliberately.

The test that matters most is the one where a model is *forced* to attempt a forbidden
action and the architecture refuses it anyway. A security control that only holds while the
model behaves is not a control.

*Status: planned.*

## 9. Known limitations

- Backends are mock systems modelled on realistic interfaces, not real IT infrastructure.
- No claim is made that prompt injection is solved, or that any security framework is
  satisfied.
- Model behaviour varies by provider; architectural properties are measured separately from
  model quality precisely because of this.
- The evaluation and ablation work needed to make the central claim measurable is not built
  yet.
