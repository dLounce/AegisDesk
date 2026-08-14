import dataclasses

import pytest

from aegisdesk.agents.state import WorkflowPhase
from aegisdesk.domain.ids import WorkflowId
from aegisdesk.evaluation.scenario import EmployeeTurn, ReviewerTurn, Scenario


def test_scenario_rejects_empty_turns() -> None:
    with pytest.raises(ValueError):
        Scenario(
            id="empty",
            workflow_id=WorkflowId("WF"),
            script={},
            turns=(),
            expected_final_phase=WorkflowPhase.RESOLVED,
        )


def test_scenario_must_open_with_an_employee_turn() -> None:
    from aegisdesk.approval import ApprovalDecision

    with pytest.raises(ValueError):
        Scenario(
            id="reviewer_first",
            workflow_id=WorkflowId("WF"),
            script={},
            turns=(ReviewerTurn("E1055", ApprovalDecision.APPROVE),),
            expected_final_phase=WorkflowPhase.RESOLVED,
        )


def test_scenario_rejects_unknown_field() -> None:
    # A frozen dataclass rejects an unexpected constructor argument, so a scenario cannot smuggle
    # an undeclared field (e.g. a control-plane handle) into the harness.
    with pytest.raises(TypeError):
        Scenario(  # type: ignore[call-arg]
            id="x",
            workflow_id=WorkflowId("WF"),
            script={},
            turns=(EmployeeTurn("E1042", "hi"),),
            expected_final_phase=WorkflowPhase.RESOLVED,
            guard="should-not-exist",
        )


def test_scenario_is_frozen() -> None:
    scenario = Scenario(
        id="x",
        workflow_id=WorkflowId("WF"),
        script={},
        turns=(EmployeeTurn("E1042", "hi"),),
        expected_final_phase=WorkflowPhase.RESOLVED,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        scenario.id = "y"  # type: ignore[misc]


def test_scenario_exposes_no_control_plane_handles() -> None:
    # The scenario dataclass must not carry a guard/access/minting-key field: its only channel to
    # the control plane is declarative turns the runner replays (agent-security F1/F2/F3).
    fields = set(Scenario.__dataclass_fields__)
    assert not (fields & {"guard", "access", "minting_key", "supervisor", "runtime"})
