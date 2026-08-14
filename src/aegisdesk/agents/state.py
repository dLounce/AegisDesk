from collections.abc import Sequence
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
    # The workflow is paused because a privileged request is missing information the employee
    # must supply. It is a distinct phase from routing so a paused turn is not mistaken for one
    # still deciding a route, and distinct from AWAITING_APPROVAL so a request waiting on the
    # employee is never confused with one waiting on a reviewer.
    AWAITING_INFO = "awaiting_info"
    RESOLVED = "resolved"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTED = "executed"
    REJECTED = "rejected"
    REFUSED = "refused"


# A single piece of information a privileged request needs before it can become a proposal.
# The three the runtime can act on: which resource, what permission, and for how long. A plain
# Enum for the reason enums.py states everywhere: a str-backed member would let raw model text
# satisfy a check that expects a slot. Which slots a given operation requires is decided in code
# (agents/escalation.py), never by the model — the model only extracts candidate values.
class InformationSlot(Enum):
    RESOURCE = "resource"
    PERMISSION = "permission"
    DURATION = "duration"


# Deterministic, templated clarification text keyed by slot. The question shown to the employee
# is never model prose: a model-authored question would be an injection surface and would make
# the workflow irreproducible. The model may help identify values; it never phrases the ask.
_QUESTION_BY_SLOT: Final[dict[InformationSlot, str]] = {
    InformationSlot.RESOURCE: "which resource you need access to",
    InformationSlot.PERMISSION: "what permission level you need (read, write, or admin)",
    InformationSlot.DURATION: "for how long you need access (one hour, eight hours, or permanent)",
}


def clarifying_question(missing: Sequence[InformationSlot]) -> str:
    parts = [_QUESTION_BY_SLOT[slot] for slot in missing]
    if not parts:
        return "To continue, please provide the missing information."
    joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + ", and " + parts[-1]
    return f"To continue, please tell me {joined}."


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
    # How many times this workflow has paused to ask the employee for missing information.
    # Bounded by the supervisor so a request that never supplies what it needs fails closed
    # rather than looping. A counter, not the answers themselves: no model-extracted slot value
    # is stored here, so the pause introduces no authoritative-state surface to poison.
    clarification_rounds: int = 0

    def tick_turn(self) -> "WorkflowState":
        return self.model_copy(update={"turns": self.turns + 1})

    def tick_handoff(self) -> "WorkflowState":
        return self.model_copy(update={"handoffs": self.handoffs + 1})

    def tick_clarification(self) -> "WorkflowState":
        return self.model_copy(update={"clarification_rounds": self.clarification_rounds + 1})

    def routed(
        self, route: AgentName, category: RequestCategory, risk_tier: RiskTier
    ) -> "WorkflowState":
        return self.model_copy(
            update={"route": route, "category": category, "risk_tier": risk_tier}
        )

    def in_phase(self, phase: WorkflowPhase) -> "WorkflowState":
        return self.model_copy(update={"phase": phase})
