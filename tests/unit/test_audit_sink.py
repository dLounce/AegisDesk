from datetime import UTC, datetime

from aegisdesk.audit import AuditEvent
from aegisdesk.backends.audit import InMemoryAuditSink
from aegisdesk.domain.enums import ActorType, AuditEventType, GuardOutcome
from aegisdesk.domain.ids import ActionId, WorkflowId

AT = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)
WORKFLOW = WorkflowId("WF-0001")
ACTION = ActionId("ACT-0000000000000000000000000000abcd")


def _executed(action: ActionId = ACTION) -> AuditEvent:
    return AuditEvent.build(
        event_type=AuditEventType.EXECUTED,
        occurred_at=AT,
        actor_type=ActorType.RUNTIME,
        workflow_id=WORKFLOW,
        action_id=action,
        outcome=GuardOutcome.EXECUTED,
    )


def _attempt() -> AuditEvent:
    return AuditEvent.build(
        event_type=AuditEventType.CROSS_EMPLOYEE_TICKET_ATTEMPT,
        occurred_at=AT,
        actor_type=ActorType.BACKEND,
        detail="requester=E1043 ticket=IT-0001",
    )


def test_a_recorded_event_is_appended_and_returned() -> None:
    sink = InMemoryAuditSink()
    event = _executed()
    assert sink.record(event) is event
    assert sink.events() == (event,)


def test_a_correlated_event_is_written_once_under_replay() -> None:
    sink = InMemoryAuditSink()
    first = sink.record(_executed())
    # A second, freshly built event under the same key is a replay of the pre-pause pass, not a
    # new occurrence: the sink keeps the first and hands it back.
    second = sink.record(_executed())
    assert second is first
    assert len(sink.events()) == 1


def test_different_event_types_for_one_action_are_distinct() -> None:
    sink = InMemoryAuditSink()
    executed = _executed()
    refused = AuditEvent.build(
        event_type=AuditEventType.REFUSED,
        occurred_at=AT,
        actor_type=ActorType.RUNTIME,
        workflow_id=WORKFLOW,
        action_id=ACTION,
        outcome=GuardOutcome.REFUSED,
    )
    sink.record(executed)
    sink.record(refused)
    assert len(sink.events()) == 2


def test_an_uncorrelated_event_is_appended_on_every_occurrence() -> None:
    sink = InMemoryAuditSink()
    sink.record(_attempt())
    sink.record(_attempt())
    assert len(sink.events()) == 2


def test_the_returned_sequence_is_not_the_stored_one() -> None:
    sink = InMemoryAuditSink()
    sink.record(_attempt())
    returned = sink.events()
    assert isinstance(returned, tuple)
    assert len(sink.events()) == 1
