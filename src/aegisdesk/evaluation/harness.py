from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from aegisdesk.agents.model import ScriptedModel
from aegisdesk.audit import AuditEvent
from aegisdesk.backends.access import AccessBackend
from aegisdesk.backends.approvals import InMemoryApprovalStore
from aegisdesk.backends.audit import InMemoryAuditSink
from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.kb import KnowledgeBase
from aegisdesk.backends.seed import (
    load_action_reversibility,
    load_approval_policy,
    load_baseline_access,
    load_employees,
    load_kb_documents,
    load_operation_risk_tiers,
    load_resources,
    load_reviewers,
    load_risk_tiers,
)
from aegisdesk.backends.tickets import InMemoryTicketStore
from aegisdesk.domain.access import AccessChange, AccessGrant, DestructiveReceipt, ExecutionReceipt
from aegisdesk.domain.enums import AuditEventType
from aegisdesk.domain.ids import ActionId, ReviewerId
from aegisdesk.evaluation.scenario import ScenarioScript
from aegisdesk.guard import RuntimeGuard
from aegisdesk.session import ReviewerSessionContext

# A fixed instant so every scenario is reproducible and time-boxed approvals behave identically
# across runs. The harness owns it; tests import it rather than redeclaring it.
AT = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)


# Records what the real backend actually issued, keyed by action id. It never mints: every method
# delegates to AccessBackend, which enforces the guard-held minting key, so the recorder observes
# authoritative issuances rather than fabricating them.
#
# Two distinct counts, deliberately not conflated. `backend_calls` counts method invocations,
# including idempotent replays that the real backend absorbs without a new side effect. The actual
# executions are the distinct action ids in the ledger (`executed_action_ids` / `execution_count`),
# deduped by action id, so a replay of an already-issued action is one execution, not two
# (agent-security F7, NON_NEGOTIABLES-adjacent idempotency). Never count method calls as executions.
class RecordingAccessBackend(AccessBackend):
    def __init__(self) -> None:
        super().__init__()
        self.backend_calls = 0
        self.issued_grants: dict[ActionId, AccessGrant] = {}
        self.recorded_changes: dict[ActionId, AccessChange] = {}

    def grant(self, receipt: ExecutionReceipt, minting_key: str) -> AccessGrant:
        self.backend_calls += 1
        issued = super().grant(receipt, minting_key)
        self.issued_grants[issued.granted_via_action_id] = issued
        return issued

    def revoke(self, receipt: DestructiveReceipt, minting_key: str) -> AccessChange:
        self.backend_calls += 1
        change = super().revoke(receipt, minting_key)
        self.recorded_changes[change.changed_via_action_id] = change
        return change

    def modify(self, receipt: DestructiveReceipt, minting_key: str) -> AccessChange:
        self.backend_calls += 1
        change = super().modify(receipt, minting_key)
        self.recorded_changes[change.changed_via_action_id] = change
        return change

    # The distinct executions the security metric scores, deduped by action id across grants and
    # destructive changes. This is the authoritative actual-execution set, not a call count.
    def executed_action_ids(self) -> set[ActionId]:
        return set(self.issued_grants) | set(self.recorded_changes)

    # The number of actual protected side effects, derived from newly recorded ledger outcomes and
    # therefore immune to idempotent replay overcounting (unlike `backend_calls`).
    @property
    def execution_count(self) -> int:
        return len(self.executed_action_ids())


# The wired control plane, built fresh from freshly-loaded seeds so no state leaks between the
# tests or scenarios that use it (agent-security F5). The guard is constructed — and claims the
# access backend's single minting authority — before any scenario-controlled artifact (the
# ScriptedModel) is built, so a scenario can never claim the key first (F1). This class holds the
# guard and access backend; it never hands them to scenario data (F3). It contains no test
# assertions: it is production wiring reused by tests, not a test fixture.
class Harness:
    def __init__(self, script: ScenarioScript, clock: Callable[[], datetime] | None = None) -> None:
        self.clock: Callable[[], datetime] = clock if clock is not None else (lambda: AT)
        self.audit = InMemoryAuditSink()
        self.directory = DirectoryBackend(load_employees(), load_baseline_access())
        self.catalog = ResourceCatalog(load_resources())
        self.tickets = InMemoryTicketStore(self.audit, clock=self.clock)
        self.access = RecordingAccessBackend()
        self.approvals = InMemoryApprovalStore(
            self.directory, load_reviewers(), load_approval_policy(), self.audit, self.clock
        )
        # Guard construction claims the minting key from self.access here, before the model exists.
        self.guard = RuntimeGuard(
            self.directory,
            self.catalog,
            self.tickets,
            load_risk_tiers(),
            self.access,
            self.approvals,
            self.audit,
            self.clock,
            operation_risk_tiers=load_operation_risk_tiers(),
            reversibility=load_action_reversibility(),
        )
        self.kb = KnowledgeBase(load_kb_documents())
        # The scenario-controlled artifact, built last.
        self.model = ScriptedModel(dict(script))
        # Imported lazily to avoid a module import cycle (workflow imports evaluation types only
        # in tests, but keeping this local documents that the harness depends on the supervisor,
        # not the reverse).
        from aegisdesk.workflow import Supervisor

        self.sup = Supervisor(
            guard=self.guard,
            approvals=self.approvals,
            tickets=self.tickets,
            directory=self.directory,
            kb=self.kb,
            model=self.model,
            audit=self.audit,
            clock=self.clock,
        )

    def reviewer(self, reviewer_id: str) -> ReviewerSessionContext:
        return ReviewerSessionContext(
            reviewer_id=ReviewerId(reviewer_id), authenticated_at=self.clock()
        )

    # A convenience query, not an assertion: returns the refused audit events for a caller to
    # inspect. Tests decide what to assert about them.
    def refused_events(self) -> Sequence[AuditEvent]:
        return tuple(e for e in self.audit.events() if e.event_type is AuditEventType.REFUSED)
