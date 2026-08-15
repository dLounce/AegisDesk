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
| Knowledge base → agent | Document contents as *data* (rendered into the DATA channel, AD-50) | Document contents as *instructions* |

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

### AD-46 — Protected operations are typed per operation, not one flat shape

`GRANT_ACCESS`, `REVOKE_ACCESS` and `MODIFY_PERMISSIONS` are three proposal subclasses of one
frozen base rather than a single record with an operation field. A revoke and a modify carry no
duration, and `extra="forbid"` means there is no field for one to arrive in — a duration on a
destructive proposal is unrepresentable rather than an ignored sentinel. The grant proposal is
unchanged, so the pinned golden action and digest vectors still hold: the canonical form omits
the `duration` key when it is absent, which keeps a grant byte-identical while giving each
destructive operation a distinct canonical form and therefore a distinct action identity.

Duration is optional through the whole resolved chain — `ResolvedAction`, `PolicyRequest`,
`PolicyDecision`, `ApprovalRecord`, the decision tuple — and a validator on each enforces that it
is present exactly for a grant. The operation travels on the policy request and decision, which is
what lets the engine decide destructive operations without inferring intent from the other fields.

*Status: implemented.*

### AD-47 — Destructive operations always require approval, and risk is keyed without a duration

A revoke or a modify never resolves automatically. Policy decides both after the existing deny
checks — an inactive requester or an unknown resource is still denied first — and before the
grant-only baseline logic, so no narrowing or reversible case is auto-allowed. Their risk tier is
keyed on the operation, the resource class and the permission, from a separate corpus, because
they have no duration to key on; the grant corpus is untouched. An unclassified triple fails
closed either way.

*Status: implemented.*

### AD-48 — Current access is authoritative backend state; reversibility is trusted config

The access backend owns what access is currently issued. A grant records it, a revoke removes it,
a modify re-points it, and `get_current_permission` is the smallest read the preconditions need.
Baseline access is not a proxy and no separate current-access corpus exists. Revoke requires that
the named permission is the one currently held; modify requires that some access exists to change.
Both are enforced in the backend against its own state, so they hold even if a caller reaches it
directly, and each maps to a distinct fail-closed guard refusal.

Reversibility is trusted configuration, recorded on the executed audit event and never read from a
proposal. A model claiming an operation is reversible cannot change how the runtime treats it.

*Status: implemented.*

### AD-49 — No silent retry of a destructive operation

The backend keeps a ledger keyed by action identifier. A completed revoke or modify returns its
recorded change on replay, so a retried resume is exactly-once. An operation whose first attempt
did not confirm completion is left marked attempted with no recorded change, and a replay of it is
refused rather than re-driven — a second irreversible side effect is never performed on an
uncertain outcome (project.md 13.6). This is deterministic idempotency at one boundary, not a
distributed exactly-once guarantee, and no such guarantee is claimed.

One consequence is deliberate and is a weaker property than the grant path has: the executed audit
event for a destructive operation is written **after** the backend confirms the change, not before
it, because an event claiming execution must not precede an outcome the backend may still refuse as
uncertain. A grant, which is safely re-drivable, keeps its fail-closed audit-before-effect ordering
(AD-45). For a destructive operation the audit-before-effect guarantee is therefore not held; if
the recording boundary fails after a confirmed change, the change stands and is re-recorded
idempotently on a later replay. This is a known limitation, consistent with the trail not yet being
durable.

*Status: implemented.*

### AD-50 — KB content is demarcated as data at a typed model-input boundary

`prompting.py` is where retrieved knowledge-base text is turned into model input. It builds a
`ModelInput` of channel-tagged `Segment` objects: `Channel.INSTRUCTION` for text authored in code,
`Channel.DATA` for everything untrusted. The channel is the boundary — it is a field set at
construction, and no code path reads a segment's text back to decide its channel, so
instruction-looking bytes inside a KB body stay data. `render_kb_document` can only emit
`Channel.DATA`, and `assemble` refuses any non-DATA segment offered in the data position, so the
untrusted-content path cannot carry instruction authority. The stored `KbDocument` is read, never
mutated; its body is embedded verbatim (the poisoned fixture flows through unchanged, unfiltered).
A nonce fence is included around each rendered body as a legibility aid and defence in depth; its
uniqueness is deliberately **not** relied on as the security boundary, because an in-band delimiter
is spoofable by construction and the channel field is what actually separates the two.

This is one layer, not a solution to prompt injection. There is no model-call consumer yet, so the
boundary is a representation that keeps untrusted text in a data channel; it does not stop a model
from being persuaded by data it is shown. The authoritative defence against an injected instruction
remains the deterministic gate (AD-1, policy, approval): even a fully hijacked agent cannot turn KB
text into a grant without policy evaluation and a human approval decision recorded against the
specific action. Scope is KB content only; ticket text and model-output demarcation are not part of
this boundary.

*Status: partial — the data-side representation is implemented and tested; no consumer model
binds it yet, and no claim is made that prompt injection is prevented.*

### AD-51 — The vertical slice is a deterministic in-process supervisor, not an agent framework

S12 wires the three agents to the control plane with the smallest orchestrator that reuses what
S1-S11 built. It is an in-process function loop, not LangGraph, and its pause/resume boundary is
`guard.propose` / `guard.execute_approved` — no separate checkpoint abstraction and no durable
store. The agents turn untrusted model output into typed decisions: the Router maps a model
category to a specialist through a fixed table (unknown category or risk fails closed); the
Resolver answers routine work through the knowledge base with no privileged capability and stops
rather than continue when a request turns privileged; the Escalation agent maps model output to a
typed proposal and calls the guard, proposing only. A scripted, deterministic model drives them,
so a scenario is reproducible and a compromised agent can be simulated by emitting exact output.

`WorkflowState` carries only trajectory fields — workflow and ticket identifiers, the routed
category, risk, and route, and the turn/handoff counters. It holds no `EmployeeSessionContext`,
no employee identity, no approval authority, no policy decision, and no capability: identity stays
authoritative runtime context re-read from the session on every step (AD-2), and a paused
workflow re-authenticates the claimed identifier on resume rather than trusting a stored one. The
supervisor makes no authorization decision itself; every such decision is delegated to the guard,
policy, and approval store. `MAX_TURNS` and `MAX_HANDOFFS` bound the loop and fail closed, so a
request that will not settle is refused rather than allowed to run away. A refusal shown to the
model is generic; the reason is recorded on the audit trail.

Known limitations, deferred to later phases: no durable checkpoint or process-restart recovery
(the pending map is in-memory), no FastAPI or reviewer UI, no live model provider, and no
evaluation harness. These are Project.md Phase 6/7/9/11 concerns; S12 is the Phase 3 slice.

*Status: implemented and tested — routine, privileged (approve and reject), scope-change, and
direct/indirect injection paths run end-to-end with unauthorized execution measured at zero.*

### AD-52 — Clarification is deterministic slot-filling, not a model-driven conversation

S13 lets a privileged request that is missing information pause and ask the employee rather than
guessing (project.md goal 3, §8.1). Four properties keep the pause from becoming a new trust
surface:

*Required slots are declared in code, per protected operation* (`agents/escalation.py`,
`_REQUIRED_SLOTS`): a grant needs resource, permission, and duration; revoke and modify carry no
duration. No configuration surface is added — the schema is version-controlled with the code that
uses it.

*The model extracts candidate values; code decides completeness.* A required slot is "missing"
only when its candidate on the model response is empty. The model can never mark a slot optional
or complete: a non-empty but invalid candidate is not treated as missing, it fails closed in
`_build` (unknown permission/duration) exactly as before, so a compromised model cannot turn a
garbage value into a clarification loop, and an absent operation is refused rather than asked.

*The question is a fixed template keyed by the missing slot* (`agents/state.py`,
`clarifying_question`). Model prose never reaches the employee as a question, which removes a
model-authored-instruction surface and keeps the workflow reproducible.

*The pause stores no authoritative state.* `WorkflowState` gains only a `clarification_rounds`
counter, never the extracted values — each turn re-classifies and re-extracts, and any resulting
privileged proposal is still re-resolved, re-digested, policy-evaluated, and human-approved by the
guard. The clarification answer is untrusted employee text: a claimed identity or self-approval in
it is ignored, because identity is re-authenticated from the session every turn and approval comes
only from the authoritative record.

Two containment controls bound the new multi-turn surface. `MAX_CLARIFICATION_ROUNDS` fails closed
so a request that never supplies what it needs is refused rather than looping (cascading-failure
control, §13.6). And the supervisor now binds each workflow to the authenticated employee who
opened it (`_owners`, keyed by directory-resolved employee id, re-checked every turn), so a second
authenticated employee cannot continue someone else's paused workflow; the refusal names no ticket,
so it is not an oracle for which workflows exist. The binding lives in runtime context, not on
`WorkflowState`, so identity still never enters the checkpoint-bound state (AD-2).

Deferred: no time-based expiry of a paused request (TTL belongs with the durable-checkpoint phase);
no cross-turn accumulation of prior message text into model context (there is no live-model
consumer yet, so transcript assembly would be speculative — it lands with the model-provider phase).

*Status: implemented and tested — missing-slot pause/resume, deterministic question, bounded
rounds, cross-employee resume refusal, and ignored-identity/approval answers run end-to-end with
unauthorized execution measured at zero.*

### AD-53 — The evaluation harness scores from authoritative state, and scenarios are data behind the control-plane boundary

S14 adds `aegisdesk.evaluation`: a deterministic scenario runner that executes declarative scenarios
through the real Supervisor/guard/approval control plane and scores three things independently, so a
correct final answer never excuses an unsafe path (project.md §17.2). The three measurements read
three different authoritative sources and never a control-plane self-report or model prose:

*task_success* reads the final `TurnResult` phase and the authoritative ticket status. *trajectory_safe*
reads the append-only audit trail — the authoritative trajectory record — and requires the full
protected-action sequence `PROPOSAL_PERSISTED → REVIEWER_DECISION(APPROVED) → EXECUTED` for the same
`action_id`, in recorded order; an `EXECUTED` event missing its proposal or approval, preceded only
by a rejection, out of order, or with a mismatched `action_id` fails the run.
*unauthorized_execution* is the security metric and reads only the minting-gated access-backend ledger
joined to the approval store: an execution is authorized only if an APPROVED approval record exists for
its exact action, so a ledger write that skipped the approval boundary counts as a bypass (fail-closed
measurement). The in-memory audit sink is corroborating evidence, never the security metric's source,
because any holder can append to it (agent-security F3/F4).

The scenario is the new trust boundary. A `Scenario` is a frozen dataclass of declarative data — a
`(agent, message) → ModelResponse` script, employee/reviewer turns, and expected state — and carries no
reference to the guard, the access backend, or the minting key (F1/F2/F3). The harness builds a fresh
control plane per scenario from freshly-loaded seeds, so no ledger, approval, ticket, or audit state
leaks between scenarios (F5); the guard claims the access backend's single minting authority at
construction, before the scripted model exists, so a scenario can never claim the key first (F1).
Executions are deduped by `action_id`, so an idempotent replay is one execution, not two (F7). A
fully-compromised-model scenario (self-approval, spoofed identity) is a permanent regression asserting
zero executions from the ledger (F6). A live model provider, pass^k, cost/latency, the simulated
employee, and durable result storage are explicitly out of S14 (later milestones); results are
in-memory objects with an optional JSON dump in the project.md §20 shape (cost/latency serialized null).

*Known limitation:* the security metric and trajectory scorer assume protected executions are
approval-gated; a within-baseline auto-allow execution (none in the current corpus) would need a
policy-allow corroboration and is deferred. The harness also surfaced a pre-existing S12 ticket/workflow
divergence — a scope change after a resolved first turn advances the workflow phase while the ticket
stays RESOLVED — recorded for later Phase 4 polish rather than fixed in S14.

*Status: implemented and tested — a 9-scenario corpus (routine, privileged approve/reject,
scope-change, clarification, direct/indirect injection, cross-employee, compromised-model) runs with
task-success 100%, trajectory-safe 100%, unauthorized-execution 0%, policy-bypass 0%, fail-closed 100%.*

### AD-54 — A live model provider sits behind the Model protocol, untrusted and fail-closed

S15 adds the first live language-model provider without changing any control. It is one
`ChatOpenAI`-compatible `LiveModel` (`agents/providers.py`) selected by configuration
(`config.py`), and it occupies exactly the seam `ScriptedModel` occupies — behind the
`Model` protocol, upstream of the Router, Resolver, Escalation, guard, policy, and approval
store. `ScriptedModel` remains the default for every unit test and local run; the live model
is built only when `AEGISDESK_MODEL_PROVIDER=openai_compatible`, and `base_url` selects
OpenAI, OpenRouter, or any OpenAI-compatible endpoint through the one class (no per-provider
subclasses; Groq and per-role model selection are deferred).

*The provider is untrusted, and its output fails closed.* The reply is parsed with an explicit
`ModelResponse.model_validate_json` — never a hidden structured-output mode — and because
`ModelResponse` forbids extra fields and types every field, a malformed reply, an unexpected
key, or a wrong-typed value raises and is caught into the default `ModelResponse`
(category `unknown`, risk `high`). Every transport failure — timeout, connection reset,
provider 5xx — is caught at the same boundary into that same safe default; nothing raises into
the workflow. The client is built with `max_retries=0`: there is no application-level or
provider-level retry (NON_NEGOTIABLES §9). Downstream, the agents still re-validate every field
against an enum and the guard re-resolves and re-authorizes independently, so a live call
influences **proposal generation only, never authorization** — a compromised or hostile
provider that returns `approve: true`, a claimed identity, or a self-approval executes nothing,
proven end-to-end through the harness.

*The provider holds no control-plane handle.* The `Model` protocol exposes only
`respond(ModelRequest) -> ModelResponse`; `LiveModel` receives no guard, access backend,
approval store, session, or minting key, and the factory passes none. The API key is a
`SecretStr` read from the environment (neutral name first, then the documented OpenAI/OpenRouter
names) and reaches only the transport client; it never enters a `ModelRequest`, a prompt, a
`ModelResponse`, an exception message, or an audit event. Incomplete live configuration fails
closed at construction (`require_live`) with a message that names the missing field, never its
value.

*The S14 harness measures live runs without making them mandatory.* `Harness` gained an optional
injected `model` (default `ScriptedModel`), so a `live`-marked smoke test can drive the real
provider through the real Supervisor while ordinary CI stays deterministic and offline
(`-m 'not live'`, plus a skip when no provider is configured). `LiveModel` records per-call
latency and provider-reported token counts as runtime telemetry (never model-authored), which
the runner aggregates into `ScenarioResult.latency_ms` and token/call counts; a scripted run
reports `None` ("not measured"). `cost_usd` stays null — a USD price table is company data,
deferred to the cost-comparison milestone rather than invented in code (AD-25).

*Status: implemented and tested — 26 new tests (config, strict parse, malformed/extra/wrong-type
rejection, timeout/connection/5xx fail-closed, no-secret-leak, factory defaults, live
self-approval executes nothing, harness injection, telemetry aggregation) plus a gated live smoke
test; scripted corpus unchanged at 100/100/0/0/100.*

### AD-55 — Measurement is injected through a per-scenario model factory; the artifact is generated, not authored

S15 gave `LiveModel` per-call telemetry but the runner could never reach it: `ScenarioRunner.run`
built its own scripted `Harness`, so `latency_ms` was structurally always `None`. S16 closes that
gap without adding a security surface. `ScenarioRunner` takes a `ModelFactory`
(`Callable[[ScenarioScript], Model]`, default `scripted_model_factory`) and builds a **fresh model
per scenario**, threaded into the existing `Harness(model=...)` seam. A measuring run is a caller
choice made at runner construction; the default stays a deterministic `ScriptedModel` rebuilt from
each scenario's own script, so ordinary runs remain offline, reproducible, and unmeasured.

*The factory is a construction-time seam, never scenario data.* A `Scenario` carries no `model` or
`model_factory` field (regression-tested); it stays declarative data behind the control-plane
boundary (AD-53). The factory receives only the scenario's `ScenarioScript` — data — and never the
guard, access backend, approval store, or minting key. The guard still claims the single minting
authority at `Harness` construction **before** the model is built, so the fresh-per-scenario model
cannot claim it first (agent-security F1). A fresh model per scenario also means telemetry, like
every other backend, never leaks across scenarios (F5).

*Telemetry is measurement-only and cannot move a security metric.* `RunReport` gained
`total_latency_ms`, `total_input_tokens`, `total_output_tokens`, `total_model_calls`, and
`measured_run_count`, aggregated **None-aware**: an unmeasured (scripted) result contributes
nothing rather than a fabricated zero, and all-None means "not measured" (project.md §17.4). The
security metrics (`unauthorized_execution_rate`, `policy_bypass_rate`, `fail_closed_rate`) are
derived from authoritative ledger and approval state and are proven identical whether or not
telemetry is present. `cost_usd` stays null (no USD price table in S16, per decision; AD-25).

*The committed benchmark is generated by the entrypoint, not hand-authored.* `python -m
aegisdesk.evaluation` (`evaluation/__main__.py`) runs the corpus scripted, prints the rate and
cost/latency summary, and writes `evaluation/results/baseline.json` via `RunReport.write_json`. The
record exposes only the approved §20 fields (`scenario_id`, `run_id`, `task_success`,
`trajectory_safe`, `policy_bypass`, `unauthorized_execution`, `cost_usd`, `latency_ms`) — no
tokens, model-call counts, `adversarial`/`executed` flags, prompt text, identity, or minting
material — and the scripted artifact is byte-identical across two runs (verified). pass^k / repeat
semantics are deferred: the factory seam is the only enabler S16 provides.

*Status: implemented and tested — 13 new tests (Scenario has no model field, factory injection
drives measurement through the runner, fresh-model-per-scenario telemetry isolation, security
rates invariant to telemetry, artifact field whitelist, None-aware aggregate math for
empty/unmeasured/mixed/measured, deterministic entrypoint artifact byte-identical across runs);
scripted corpus unchanged at 100/100/0/0/100.*

### AD-56 — Golden trajectories score an acceptable path, orthogonally to task success and security

S17 adds a third, independent evaluation axis: did the workflow take an *acceptable* path, not just
reach a correct final state (`task_success`) or avoid a security-lifecycle violation
(`trajectory_safe`). It is a pure scorer (`evaluation/trajectory.py`) over an `ObservedTrajectory`
and a declarative `TrajectoryRubric`, both evaluation data. The rubric composes four typed checks:
an ordered `AgentPathCheck`, an ordered `PhasePathCheck`, one or more `ActionLifecycleCheck`s keyed
by `ProtectedOperation`, and a `ForbiddenEvents` set. Each check has an `EXACT` or `SUBSEQUENCE`
match mode, so a rubric can pin a precise sequence or admit legitimate bounded variants. `Scenario`
gained an optional `rubric` field (pure data); all 11 corpus scenarios declare one, including two
new destructive golden scenarios (`revoke_access_approved`, `modify_permissions_approved`) built on
legitimate seed access — a prod-db admin grant is approved and executed, establishing current
access, then revoked/modified under a second approval, so every execution stays proposal- and
approval-paired and the trajectory remains safe.

*The observed trajectory is authoritative or evaluation-only, never model prose.* Phase path comes
from the real Supervisor's per-turn `TurnResult.phase`; the audit event sequence is the append-only
trail, and each `ActionLifecycleCheck` reads the operation from the `PROPOSAL_PERSISTED` event's
authoritative `PolicyDecision.operation`, never from model output. The agent path is captured by an
evaluation-only `_AgentPathRecorder` that wraps the scenario's model, records `request.agent`, and
delegates `respond` unchanged; it is built fresh per scenario, holds no guard/access/approval/
minting handle (the `Model` protocol exposes none), and its observation is never an authorization
input.

*Acceptability is orthogonal to task success and to every security metric.* `trajectory_acceptable`
is `True`/`False` when a rubric is present and `None` when absent ("not evaluated", never silently
acceptable). A forbidden path fails acceptability even when `task_success` is true — proven both as
a pure-scorer test (an executed-but-forbidden trajectory) and end-to-end (a deliberately wrong
rubric on a successful scenario). Security metrics (`trajectory_safe`, `unauthorized_execution`,
`policy_bypass`, `fail_closed`) are proven identical with rubrics present and stripped; the golden
score never feeds them. Per project decision, `trajectory_acceptable` is **not** serialized: the
committed §20 artifact keeps its fixed field whitelist, and only the aggregate
`trajectory_acceptable_rate` / `trajectory_scored_count` are printed; `trajectory_score` is an
in-memory diagnostic. `TrajectoryReport.acceptable` gates on all checks passing.

*Status: implemented and tested — 18 new tests (agent/phase EXACT and SUBSEQUENCE, full/partial/
rejected lifecycle, operation-required, decision-status matching, forbidden-event orthogonality,
score/empty-rubric, no-control-plane-import guardrail, corpus all-acceptable, wrong-rubric
orthogonality end-to-end, security-rate invariance to rubric presence, unrubriced-not-scored,
destructive scenarios executed and authorized, rate aggregation). Corpus is 11 scenarios at
100 task-success / 100 trajectory-safe / 100 trajectory-acceptable / 0 unauthorized / 0
policy-bypass / 100 fail-closed.*

### AD-57 — The live persona employee is a live-model input generator, never a control-plane actor

S20 gives the simulated employee (AD, S18) a live-model backing so later reliability evaluation can
measure genuine model-input stochasticity instead of S19's seeded phrasing selection.
`LivePersonaEmployee` (`evaluation/live_persona.py`) implements the same `SimulatedEmployee`
protocol behind the runner's existing `EmployeeFactory` seam; it is an input/test generator and
does **not** address task integrity or prompt injection.

*Same untrusted shape, no new capability.* Like `SeededPersonaEmployee`, the live employee holds no
guard, access backend, approval store, session, minting key, reviewer capability, or policy object —
the protocol exposes none and `live_employee_factory` passes none. Its only output is
`(claimed_id, message) | None`, and `claimed_id` is always the persona's, never chosen by the model:
an identity-confusion attempt is therefore confined to message *content*, which the session still
authenticates against the directory (identity invariant unchanged). It receives only the enum-only
`EmployeeObservation` (phase + missing slots); no agent- or model-authored prose is ever exposed to
it, preserving the S18 closure of the system-output→instruction channel. Reviewers stay scripted and
trusted — the employee surface has no decision/approval method, so a simulated employee can never
render a reviewer verdict.

*Fail-safe, never fail-open.* Any provider timeout, transport error, malformed reply, or empty
output is caught and reduced to a safe value — an empty opening message or a stopped reply (`None`)
— which drives the workflow toward clarification or refusal. Because every authorization is
downstream and independent of this input, a failing or actively hostile employee model can only make
a scenario *fail*; it can never produce an execution or an approval (regression-tested end-to-end: a
compromised employee that classifies to a full grant and tries to self-approve still pauses at
approval and executes nothing).

*Independent configuration and isolated telemetry.* The employee model reads its own
`AEGISDESK_PERSONA_MODEL_*` namespace (`PersonaModelSettings`) with a nonzero sampling `temperature`
as the stochasticity knob, deliberately separate from the agent model's `AEGISDESK_MODEL_*`: the
employee model is the harness, not the system under test, and coupling the two configs would let one
change alter both. It shares only the stateless `build_chat_client` transport, built fresh per
persona (hence per scenario/trial) so no mutable state crosses trials (the `run_passk`
factory-statelessness contract, agent-security F5). The live employee's own call telemetry is
harness diagnostics and is never merged into `ScenarioResult` cost/latency, which continue to
describe only the SUT model.

*Gated and offline by default.* The default `ScenarioRunner` and `run_passk` still use
`SeededPersonaEmployee`; a live employee is opt-in via an injected factory. The live path is
exercised only by a single `pytest.mark.live` smoke test (one provider call, skipped unless
configured), excluded from the default `-m 'not live'` run. Measured live runs are non-deterministic
and are never committed as baseline artifacts (NON_NEGOTIABLES §9). S20 delivers only the seam; a
live pass^k reliability run and the seeded-vs-live comparison are S21.

*Status: implemented and tested — 14 new offline tests (claimed_id fixed to persona; identity-claim
confined to content; reply speaks only while awaiting info; slot hint is non-verbatim; fail-safe on
provider error/empty for both opening and reply; oversized output bounded; no reviewer-decision
surface; compromised-employee cannot self-approve or execute; persona telemetry excluded from SUT
metrics; factory fails closed on incomplete config; independent config with nonzero default
temperature; fresh stateless client per trial) plus one gated live smoke test. Full offline suite
966 pass; scripted corpus and committed baseline/passk artifacts byte-identical and unchanged.*

### AD-58 — Live pass^k measures reliability with both models live; security stays authoritative

S21 runs the S19 pass^k corpus with **both** the simulated employee and the SUT agent model backed by
real providers (`evaluation/passk_live.py`). The design forcing function is that a `ScriptedModel`
keys on exact message strings and cannot classify a live employee's free-form text, so a meaningful
live reliability measurement requires the agent model to be live too. Both models are untrusted; the
experiment's headline claim is that the deterministic authorization boundary holds under a fully
stochastic, untrusted model pipeline.

*Composition, not new mechanism.* The module only wires the existing seams: `ScenarioRunner`'s
`model_factory` returns a fresh `LiveModel` per trial and its `employee_factory` a fresh
`LivePersonaEmployee` per trial, both fed to the unchanged `run_passk`. Each trial still builds a
brand-new `Harness` (fresh guard/access/approval/audit/directory/tickets), so no control-plane state
crosses trials (agent-security F5). Neither factory receives a guard/access/approval/session/minting/
reviewer/policy handle — only the scenario's `script`/`persona` data. `runner.py`, `passk.py`,
`report.py`, `persona.py`, and `live_persona.py` are untouched, as are the deterministic
`__main__.py`/`passk.py` entrypoints and their committed `baseline.json`/`passk.json`. The corpus is
reused unchanged except that each persona now carries a natural-language `goal` (the live employee's
task contract); the seeded employee ignores `goal` and it is unserialized, so S19 stays
byte-identical (verified).

*Security is strict and un-averaged.* Per-trial security flags come from authoritative ledger/approval/
audit state, and pass^k aggregates them as **any-fail counts** — one unauthorized execution or policy
bypass in one trial fails the corresponding result regardless of the other trials. A live agent model
does not weaken this: its output is re-validated against enums and re-authorized by the guard, and its
`approve`/`claimed_employee_id` fields are ignored, exactly as for a scripted model. The live employee
still emits only `(claimed_id, message) | None`.

*Spend control and determinism boundary.* A single `CallBudget` is shared by both models' transports
via `_BudgetedChatClient`, charged before each provider call; exhausting it raises inside the
transport, where `LiveModel`/`LivePersonaEmployee` already fail closed — so the ceiling caps actual
spend and degrades to safe scenario failures, never an execution. The full manual run is 3 scenarios ×
K=3 under an ~80-call default budget; the automated `pytest.mark.live` smoke is exactly one scenario ×
K=1 and is skipped unless both providers are configured. Live diagnostics (per-trial security flags,
SUT telemetry, employee telemetry reported separately, full transcripts) are written **outside the
repository** by default and the writer refuses any `evaluation/results` or `baseline.json`/`passk.json`
path; live output is never committed, and `require_live()` gates both configs before any network
object is built.

*Regression capture is deterministic and human-reviewed.* A failing live trial can be reproduced by
`capture_trial`, which re-runs one scenario through a recording SUT model to capture the exact
`(agent, message) → ModelResponse` mapping, and `render_scenario_source`, which emits a
ScriptedModel-backed scenario as source text for a person to review before adding it to the offline
corpus. Nothing is auto-committed.

*Status: implemented and tested — 11 new offline tests (budget charge/fail-closed, no call past the
ceiling, employee-over-budget safe-empty, fresh employee instances + telemetry retention, committed-
path rejection, require-live fail-closed, end-to-end offline routine reliable+secure, per-trial
security flags preserved in diagnostics, seeded-vs-live comparison shape, recording-model capture,
capture→freeze deterministic reproduction) plus one gated live smoke (1 scenario × K=1). Full offline
suite green; committed baseline/passk artifacts byte-identical and unchanged. A live run is manual,
non-deterministic, uncommitted.*

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
| Goal hijack via injected instructions | Untrusted-content separation; policy outside the model | Partial — the S12 supervisor drives Router/Resolver/Escalation through the guard; injected instructions (direct or via KB) reach no authorization because agents only propose and the guard decides (AD-50, AD-51). Prompt injection is not claimed solved |
| Tool misuse | Strict argument schemas, enumerated permissions, resource catalogue | Partial — the Escalation agent maps model output to a typed proposal fail-closed and the guard re-validates; the Resolver holds no privileged capability (AD-51) |
| Identity and privilege abuse | Session-derived identity, self-scoped reads, least-privilege capabilities | Partial |
| Unexpected code execution | No arbitrary execution capability exists | Not started |
| Memory and context poisoning | Authoritative approval lookup; conversation text cannot authorize | Partial — the store is authoritative and no path reaches it from text; the workflow memory it will sit beside does not exist yet |
| Insecure inter-agent communication | Structured typed handoffs with explicit reasons | Partial — the supervisor passes typed routing/proposal state between agents (AD-51); no free-form natural-language handoff carries authority. Cross-process/authenticated inter-agent messaging is out of scope |
| Cascading failures | Turn, handoff, and tool-call limits; fail-closed defaults | Partial — MAX_TURNS and MAX_HANDOFFS bound the S12 supervisor and fail closed on exhaustion (AD-51); tool-call limits and workflow deadlines are not yet added |
| Human-agent trust exploitation | Reviewers see the raw proposed action, not a model summary | Partial — the approval record and the paused turn expose the resolved action, not agent prose; no reviewer interface exists yet |
| Rogue agent behaviour | Fixed capability sets and termination limits | Partial — capability sets are enforced and the supervisor has termination limits (AD-51); a compromised Router can still reach Escalation, which the guard contains at the approval boundary |

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
- A destructive operation records its executed audit event after the backend confirms the change
  rather than before it (AD-49), so the fail-closed audit-before-effect ordering the grant path
  has is not held for revoke and modify. A confirmed change whose audit write then fails stands
  and is re-recorded idempotently on replay. This is bounded by the same non-durable-trail
  limitation above.
- Current access is modelled as backend state seeded by grants performed in-process; it is not a
  connection to a real identity provider, and use-time enforcement of a permission is still not
  built (AD-44).
