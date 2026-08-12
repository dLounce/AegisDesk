# AegisDesk

**Multi-agent IT and access operations with a deterministic, human-gated security control plane.**

> **Status: early development.** The repository scaffold is in place. No agent, policy,
> or approval functionality is implemented yet. Nothing in this README describes behaviour
> that exists today unless it is marked as implemented. See [Implementation status](#implementation-status).

---

## What this is

AegisDesk is an internal IT and access helpdesk for a fictional ~500-person technology
company. It handles the ordinary traffic of an IT queue — VPN problems, password resets,
software and licence requests, laptop issues, standard application access — and resolves
the routine cases autonomously where policy permits.

It also handles the cases that are *not* routine: privileged access grants, production
changes, deprovisioning, destructive operations. Those stop at a human approval gate before
the protected tool is allowed to run.

## Why it is built this way

The interesting engineering problem is not "can an agent close a ticket". It is:

> How do you give an AI system real operational autonomy without letting the model itself
> become the security boundary?

The organising principle of this codebase:

> **The model can propose an action. The application decides whether that action is allowed.**

The model is genuinely useful for classification, clarification, routing, troubleshooting,
and proposing actions. It is not trusted to establish identity, invent authorization,
reinterpret policy, bypass approval, or decide whether a privileged action is safe. Those
decisions belong to deterministic code and to authoritative backend state.

## Architecture

```
Employee (authenticated session)
        │
        ▼
   FastAPI service
        │
        ▼
  LangGraph workflow
        │
   ┌────┴─────┬──────────────┐
   ▼          ▼              ▼
 Router    Resolver     Escalation
   │          │              │
   └──────────┴──────────────┘
              │
              ▼
    Runtime guard  ── capability check
                   ── strict schema validation
                   ── deterministic policy evaluation
              │
      ┌───────┴────────┐
      ▼                ▼
 safe execution   protected action
                       │
                       ▼
              durable approval record
                       │
              human reviewer decision
                       │
                       ▼
              backend execution (idempotent)
                       │
                       ▼
                  audit trail
```

Three agents, with deliberately unequal capabilities:

| Agent | Owns | Notably cannot |
| --- | --- | --- |
| **Router** | Classification, risk tiering, detecting missing information, routing | Call any tool |
| **Resolver** | Routine, policy-bounded support | Reach the access API at all |
| **Escalation** | Privileged and ambiguous work | Authorize its own proposals |

The capability restriction on the Resolver is enforced by tool binding *and* by an
independent check inside the runtime guard — not by an instruction in a prompt.

## The security boundary

The guard is the single path to any protected operation, and it lives inside the tool
implementation rather than in a graph node, so no routing decision can skip it.

Because a workflow that pauses for human approval will re-execute the paused code when it
resumes, the ordering is a hard design constraint:

**Before the pause** — deterministic validation, capability check, schema validation,
policy evaluation, idempotent proposal persistence, idempotent audit write. No
non-idempotent side effect of any kind.

**After the pause** — re-read the authoritative approval record from the store, require an
approved status, recompute and verify the digest of the exact arguments, re-read requester
and resource state, re-run policy, then execute through the backend using the action id as
an idempotency key, and record the execution.

The resume payload is never treated as authoritative approval state.

## Implementation status

| Capability | Status |
| --- | --- |
| Repository scaffold | Implemented |
| Domain models, policy engine, backends | Not started |
| Runtime guard and capability registry | Not started |
| Router / Resolver / Escalation agents | Not started |
| Durable approval and resume | Not started |
| HTTP API | Not started |
| Security and adversarial test suite | Not started |
| Evaluation harness | Not started |

This table is updated as each piece lands. It is intended to be accurate rather than
aspirational.

## Getting started

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Copy `.env.example` to `.env` and fill in credentials when the model layer lands. `.env` is
git-ignored and must never be committed.

## Design documentation

[`DESIGN.md`](DESIGN.md) covers trust boundaries, the architectural decisions behind the
control plane, the threat model, and known limitations.

## Known limitations

Recorded honestly, and expanded as the system grows:

- Nothing is implemented yet beyond the scaffold, so no security property has been demonstrated.
- Backends are mock systems. They imitate the interfaces, authorization boundaries, and
  failure modes of real internal IT systems; they are not real ones.
- This project does not claim compliance with any security framework, and does not claim
  that prompt injection is solved.
