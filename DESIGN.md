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

*Status: implemented.* The digest is computed on every resolved proposal, stored on the
approval record, and recomputed and compared by `RuntimeGuard.execute_approved`. Because the
digest covers the policy version, a rule edit between approval and execution shows up here as a
mismatch that can be reported.

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

*Status: implemented.* Proposal persistence is insert-if-absent under the workflow and action
identifiers, so repeating the pre-pause pass produces one record with one creation time and does
not reset a decision. The audit write now exists with the same property: `InMemoryAuditSink` is
insert-if-absent under `(workflow_id, action_id, event_type)`, so a correlated event replayed on
resume records one entry rather than a duplicate. A pre-resolution refusal has no action identity
and is therefore uncorrelated and recorded on every genuine attempt, which is the intended
behaviour rather than a gap: a repeated refusal is a distinct line, not a replay of one.

### AD-6 — Agents may propose privileged actions; they may not execute them

Capability sets distinguish proposing from executing. No agent holds execute authority for
protected operations. Execution authority belongs to the runtime, and only after an
authoritative approval has been read back from the store.

*Status: implemented.* Capability sets distinguish proposing from executing, no agent holds
execute authority, and execution after an approval happens inside the runtime guard against a
record it fetched for itself. Proposing an approval-requiring action returns a pending outcome;
only `execute_approved` can turn one into a grant.

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

The approval record is fetched by the workflow and action identifiers **the runtime guard
derives inside `execute_approved`**, never by an identifier supplied in the resume payload and
never by one carried over from the proposing pass. A payload-supplied key would let a genuine
approval for one action authorise a different one, and every subsequent check would pass because
the record itself is real.

Execution then requires that the re-evaluated policy version, effect, reason, requester,
resource, permission and duration are identical to the tuple recorded on the approval. Whole
decision records cannot be compared: the evaluation timestamp legitimately differs between the
proposing pass and the resuming one. Any difference in the semantic tuple fails closed,
including a change that would now permit the action outright, because a changed world is a
world the reviewer did not authorise.

*Status: implemented.* `RuntimeGuard.execute_approved` derives the key, and the five checks it
runs are listed under AD-38.

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

### AD-38 — The resume path is a second guard method that re-resolves everything

Approval creates a second way into protected execution, and where it lives decides whether the
first one's guarantees survive. `RuntimeGuard.execute_approved` therefore takes exactly what
`propose` takes — an agent, a session, a workflow identifier and a proposed action — and repeats
the whole resolution sequence before looking anything up.

Nothing resolved may be handed back in. A `ResolvedAction` is an importable, constructible record
with no provenance, so a caller that built one naming another requester and then derived the
identifier and the digest from that same record would produce a self-consistent triple: the
identifier would match, the digest would match, and every comparison would pass because both
sides came from the caller. That is the shape of the three defects already closed for
caller-built resources, caller-supplied baselines and look-alike sessions. The method signature
is the control: there is no parameter for a resolved action, an action identifier, an argument
digest, a policy decision, an approval identifier or an approval record.

The minting key stays private to the guard for the same reason. Handing it to a store or a
workflow node so that something else could execute would make the backend's single minting
authority decorative.

Having re-resolved, the guard runs five checks against the record and fails closed on each: the
record exists under the derived key; its effective status is approved; the recomputed argument
digest matches; the re-evaluated decision tuple matches; and the reviewer who decided is still
eligible. The fourth refuses even when the re-evaluated decision would now permit the action
outright.

*Status: implemented.*

### AD-39 — Only an approval-requiring decision opens a record

`REQUIRE_APPROVAL` opens an authoritative record and returns; `DENY` writes nothing and `ALLOW`
executes without one. A denied action reaching a reviewer would let a human authorise what policy
already refused, which is the precedence the rule order exists to preserve, so the record type
refuses to hold anything but a `REQUIRE_APPROVAL` decision.

Opening is insert-if-absent under `(workflow_id, action_id)`. Everything before a pause runs
again on resume, so a repeated pass returns the record the first one wrote — same identifier,
same creation time, same status. A rejection is therefore not reset by re-proposing, and a
reviewer is not notified twice for one action.

Because the record that comes back may already be decided, the proposing pass reads its state
rather than assuming it is pending. A pending record and an approved one are both gated: the
proposing pass never executes, so the action is still waiting on the resume path either way, and
both report the same sentence so that a reply cannot tell an agent the moment its action cleared
the gate. A rejected record and a lapsed one are refusals with reasons of their own, because
reporting a pending outcome for either would tell a workflow to wait for a decision that has
already been made or can no longer be made — and, in the rejected case, would hand an agent a
second reviewer for an action a human turned down. The states that may report gated are a
permit-list, so a status with no entry refuses.

A workflow may hold only a bounded number of pending records. Because a derived identifier makes
a re-proposal idempotent, the way to manufacture reviewer fatigue is to vary one field until the
queue is full of near-identical requests; the bound is a containment limit of the kind the
project already applies to handoffs and tool calls, not a policy value.

*Status: implemented.*

### AD-40 — Reviewer authorisation is a stated roster, not a derived role

No governing document says which employees may decide which approvals. Deriving a roster from
`EmployeeRole` would put a company policy value into code, which the policy engine has
consistently declined to do, so the roster is explicit seed configuration: a flat list of
identifiers, with absence a refusal. It is deliberately not keyed on resource class or risk tier,
because no document states such a scoping rule either.

Eligibility is three questions, asked when the decision is made and asked again when the workflow
resumes: is this identifier on the roster, is the person still active, and are they someone other
than the requester. Roster membership is matched exactly, because it asks whether an identifier
was issued. Self-approval is compared case-insensitively, because it asks whether two identifiers
name the same person, and a spelling that differs only in case must still count as the same
person rather than as a way past the rule.

**Known limitation.** `authenticate_reviewer` verifies a well-formed identifier against the
directory. It is not a credential check and is not cryptographic authentication. Until it is, the
strength of the approval boundary is bounded by "an attacker who knows a second valid employee
identifier that appears on the roster", and the roster is what bounds it.

*Status: implemented.*

### AD-41 — Approval expiry is derived from the record, never written to it

A record carries two deadlines: how long a reviewer has to decide, and how long an approval stays
executable once granted. Both are read from the record rather than swept into it by a job, so the
answer does not depend on whether the sweep ran, and a resume cannot find a record that a crash
left un-expired. `EXPIRED` is consequently not a status anything stores and not a destination in
the transition permit-list, which leaves the reviewer's own decision as the only write.

The two windows answer different questions. The pending window bounds how long a request may sit
in a queue. The approved window bounds the gap between a human authorising an action and the
action happening, which is the interval in which the world can change underneath a decision
already made.

`SUPERSEDED` stays reserved and unreachable. Because the action identifier is derived, an amended
action is a different action with its own record, and the original lapses on its own deadline.

*Status: implemented.*

### AD-42 — The guard owns an injected clock

Approval freshness, grant windows and lapsed-replay checks are all decisions about time, so the
instant is not a per-call argument. A caller that supplied it could make a stale approval look
fresh and could choose the window of every grant it asked for. The guard and the approval store
each take a clock at construction, in the way the ticket store already does, which keeps tests
deterministic without any component reading the system clock at the point of use.

*Status: implemented.*

### AD-43 — Awaiting approval is a third outcome, not a flavour of refusal

A paused action is not a denied one: it produces a record, it is audited differently, and the
workflow has to pause rather than report a refusal. The guard outcome therefore has three
members, and the outcome record's invariants differ per member — an executed outcome carries a
grant, a pending outcome carries an approval identifier and no grant, and a refusal carries a
reason and neither.

This is the one distinction the model is allowed to draw. Refusals all share a single sentence so
that a compromised agent cannot search the argument space by comparing replies; a pending action
gets its own sentence, because the employee is told a human is looking. That sentence still names
no resource, no rule and no reviewer, and the precise refusal reason continues to travel only on
the outcome record.

*Status: implemented.*

### AD-44 — A lapsed grant is not replayed as a success

The access backend returns the grant it already issued for an action identifier, which is what
makes a retried execution safe. Once that grant's window has closed, returning it would report a
success that is not one: the outcome would say the access was granted while the grant it carried
had already expired, and the audit trail would read as a fresh authorisation. A replay in that
state is refused instead, and a renewal has to be a new action — new ticket, new identifier, new
digest, new approval.

This is narrowly a replay check on the execution path. Nothing in the system yet revokes a grant
or checks one at the time it is used, and `PERMANENT` grants have no window at all. Use-time
enforcement is a later concern and is not claimed here.

*Status: implemented.*

### AD-45 — The audit trail records authoritative state, escaped at the log boundary

The trail records the trajectory of a protected action — persisted, awaiting a human, executed,
refused — plus the two security-relevant events off that path: a reviewer's decision and a
cross-employee ticket attempt. Every field on an `AuditEvent` is authoritative runtime state or a
bounded, escaped descriptor; the whole validated `PolicyDecision` travels on the event, so a line
is self-describing without a join, and nothing a model wrote reaches the trail as prose. The one
distinction the model may draw still holds: the refusal reason travels only here, never in the
sentence the model is handed (AD-35).

Two properties are enforced structurally. The executed write precedes the grant and fails closed,
so a grant cannot be issued that the trail did not record; every other event is best-effort,
because none authorises anything and a failed write must not change an already-non-executing
outcome. And any caller-influenced string — `detail`, `actor_id` — passes `sanitize_log_field` at
construction, which escapes newlines and control characters and bounds length (ASVS V7.3.1), so a
message body cannot forge a neighbouring log line. Escaping happens at the log boundary only; the
stored ticket and KB text are never mutated, in the way the KB is never sanitised in place.

The same `AuditSink` is injected into the guard, the ticket store and the approval store rather
than placed behind a facade: each component records the events only it can see, and the
cross-employee attempt in particular is recorded by the store because it is the one place that can
still tell a cross-employee access from a missing ticket before both collapse into the identical
caller-facing error.

*Status: implemented.* `InMemoryAuditSink` is the append-only recording boundary. It is not
durable non-repudiation: the trail lives in process memory and a restart loses it. Durable,
tamper-evident storage is the §5 persistence concern.

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

*Status: partially implemented.* The two passes exist as `RuntimeGuard.propose` and
`RuntimeGuard.execute_approved`, they share their resolution sequence by construction, and the
proposal and audit writes between them are idempotent. The executed event is written before the
grant is minted and fails closed: if the recording boundary raises, the exception propagates and
no grant is issued. The proposal, pending, refused, reviewer-decision and cross-employee events
are recorded best-effort, because none of them authorises anything and a failed write must not
convert a refusal or a pause into a different outcome. What is still not built is the workflow
that pauses between the two passes, so the ordering is enforced by the code that exists rather
than demonstrated across a real checkpoint, and the sink holds the trail in process memory —
durable, tamper-evident non-repudiation is a §5 persistence concern, not a property claimed here.

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
| Memory and context poisoning | Authoritative approval lookup; conversation text cannot authorize | Partial — the store is authoritative and no path reaches it from text; the workflow memory it will sit beside does not exist yet |
| Insecure inter-agent communication | Structured typed handoffs with explicit reasons | Not started |
| Cascading failures | Turn, handoff, and tool-call limits; fail-closed defaults | Not started |
| Human-agent trust exploitation | Reviewers see the raw proposed action, not a model summary | Partial — the approval record holds the resolved action and the policy decision and carries no agent prose; no reviewer interface exists yet |
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
