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

*Status: planned.*

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

*Status: planned.*

### AD-4 — Action identifiers are derived deterministically

Code containing a workflow pause re-executes when the workflow resumes. A randomly
generated identifier would differ between the proposing pass and the resuming pass and
would silently break approval binding. Identifiers are derived from stable workflow inputs.

*Status: planned.*

### AD-5 — No non-idempotent side effect before the pause

A direct consequence of AD-4. Proposal persistence and the corresponding audit write are
idempotent upserts, so a second pass over the same code is a no-op rather than a
duplicate.

*Status: planned.*

### AD-6 — Agents may propose privileged actions; they may not execute them

Capability sets distinguish proposing from executing. No agent holds execute authority for
protected operations. Execution authority belongs to the runtime, and only after an
authoritative approval has been read back from the store.

*Status: planned.*

### AD-7 — Classification runs on every inbound message

Re-classifying each turn means a conversation that changes scope mid-way — a routine
troubleshooting thread that turns into a privileged access request — is caught
structurally, without a special-purpose detector, and without the workflow inheriting the
risk tier it started with.

*Status: planned.*

### AD-8 — An explicit bounded tool loop rather than a prebuilt agent runtime

An explicit loop keeps per-agent capability binding, turn and handoff limits, and
trajectory logging visible in the codebase, which the evaluation work depends on. It also
avoids a deprecated framework entry point and the dependency it would pull in.

*Status: planned.*

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

*Status: not started.* The producer lands with the runtime guard.

### AD-29 — Session context is re-supplied on resume and compared by value

The session record is not a field on workflow state and is not read back from a checkpoint as
authoritative. The API layer supplies it on the first invocation and again on each resume,
and the resuming pass compares the value it was handed to the value the run started with. It
is frozen and closed to unknown fields so that comparison means what it appears to mean.

*Status: partially implemented.* The record and its comparison semantics exist; the
enforcement point lands with the workflow.

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
| Tool misuse | Strict argument schemas, enumerated permissions, resource catalogue | Not started |
| Identity and privilege abuse | Session-derived identity, self-scoped reads, least-privilege capabilities | Not started |
| Unexpected code execution | No arbitrary execution capability exists | Not started |
| Memory and context poisoning | Authoritative approval lookup; conversation text cannot authorize | Not started |
| Insecure inter-agent communication | Structured typed handoffs with explicit reasons | Not started |
| Cascading failures | Turn, handoff, and tool-call limits; fail-closed defaults | Not started |
| Human-agent trust exploitation | Reviewers see the raw proposed action, not a model summary | Not started |
| Rogue agent behaviour | Fixed capability sets and termination limits | Not started |

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
