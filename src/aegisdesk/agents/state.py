from enum import Enum
from typing import Final

from pydantic import BaseModel, ConfigDict

from aegisdesk.domain.enums import AgentName, RiskTier
from aegisdesk.domain.ids import TicketId, WorkflowId


# The request classes the Router recognises. A plain Enum for the reason enums.py states: a
# str-backed member would let a raw model string satisfy a check that expects a category.
class RequestCategory(Enum):
    KB_QUESTION = "kb_question"
    ROUTINE_SUPPORT = "routine_support"
    ACCESS_REQUEST = "access_request"
    DESTRUCTIVE_ACCESS = "destructive_access"


class WorkflowPhase(Enum):
    ROUTING = "routing"
    RESOLVED = "resolved"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTED = "executed"
    REJECTED = "rejected"
    REFUSED = "refused"


# The categories that must reach Escalation rather than the Resolver. Membership is what the
# Resolver checks its own re-classification against, so a routine path that turns privileged
# mid-conversation is a scope change rather than something the Resolver answers.
PRIVILEGED_CATEGORIES: Final[frozenset[RequestCategory]] = frozenset(
    {RequestCategory.ACCESS_REQUEST, RequestCategory.DESTRUCTIVE_ACCESS}
)

_CATEGORY_BY_NAME: Final[dict[str, RequestCategory]] = {c.value: c for c in RequestCategory}


def category_from_name(name: str) -> RequestCategory | None:
    return _CATEGORY_BY_NAME.get(name)


# The workflow's own state. It carries what the trajectory needs and nothing the security
# controls own: no EmployeeSessionContext, no employee identity, no approval authority, no
# policy decision, no capability, no minting credential. Identity is authoritative runtime
# context re-read from the session on every step (DESIGN.md AD-2), so a value copied here
# could go stale across a pause and be trusted anyway. `extra="forbid"` makes adding such a
# field a construction error rather than a review comment.
class WorkflowState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    workflow_id: WorkflowId
    ticket_id: TicketId
    category: RequestCategory | None = None
    risk_tier: RiskTier | None = None
    route: AgentName | None = None
    phase: WorkflowPhase = WorkflowPhase.ROUTING
    turns: int = 0
    handoffs: int = 0

    def tick_turn(self) -> "WorkflowState":
        return self.model_copy(update={"turns": self.turns + 1})

    def tick_handoff(self) -> "WorkflowState":
        return self.model_copy(update={"handoffs": self.handoffs + 1})

    def routed(
        self, route: AgentName, category: RequestCategory, risk_tier: RiskTier
    ) -> "WorkflowState":
        return self.model_copy(
            update={"route": route, "category": category, "risk_tier": risk_tier}
        )

    def in_phase(self, phase: WorkflowPhase) -> "WorkflowState":
        return self.model_copy(update={"phase": phase})
