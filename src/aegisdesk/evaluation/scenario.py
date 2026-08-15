from collections.abc import Mapping
from dataclasses import dataclass

from aegisdesk.agents.model import ModelResponse
from aegisdesk.agents.state import WorkflowPhase
from aegisdesk.approval import ApprovalDecision
from aegisdesk.domain.enums import AgentName, TicketStatus
from aegisdesk.domain.ids import WorkflowId
from aegisdesk.evaluation.trajectory import TrajectoryRubric

# A scenario is declarative data and nothing else. It carries no reference to the guard, the
# access backend, or a minting key, and no live model — only a script the runner feeds to a
# ScriptedModel and the turns it drives. This is the trust boundary the evaluation harness sits
# behind: a scenario cannot reach the control plane except by describing employee/reviewer turns
# the runner replays through the real Supervisor (DESIGN AD-53, agent-security F1/F2).


@dataclass(frozen=True)
class EmployeeTurn:
    claimed_id: str
    message: str


@dataclass(frozen=True)
class ReviewerTurn:
    reviewer_id: str
    decision: ApprovalDecision


Turn = EmployeeTurn | ReviewerTurn

# The script a ScriptedModel is built from: an untrusted (agent, message) -> ModelResponse map.
# A fully-compromised model is expressed by scripting adversarial responses, which is how the
# harness measures containment rather than assuming it.
ScenarioScript = Mapping[tuple[AgentName, str], ModelResponse]


@dataclass(frozen=True)
class Scenario:
    id: str
    workflow_id: WorkflowId
    script: ScenarioScript
    turns: tuple[Turn, ...]
    expected_final_phase: WorkflowPhase
    expected_ticket_status: TicketStatus | None = None
    # Marks an attack scenario, so the aggregate report can compute a fail-closed rate over the
    # adversarial subset.
    adversarial: bool = False
    # The scenario must produce no protected execution at all. True for attacks and for requests
    # that must fail closed; drives the policy-bypass check (an execution here is a bypass).
    must_not_execute: bool = False
    # The golden trajectory this run should follow. Pure evaluation data (enums and tuples, no
    # control-plane handle); scored into `trajectory_acceptable` and never an authorization input.
    # None means the scenario declares no golden path and is not trajectory-scored.
    rubric: TrajectoryRubric | None = None

    def __post_init__(self) -> None:
        if not self.turns:
            raise ValueError("a scenario needs at least one turn")
        if not isinstance(self.turns[0], EmployeeTurn):
            raise ValueError("a scenario must open with an employee turn")
