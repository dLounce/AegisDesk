from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aegisdesk.backends.access import AccessBackend
from aegisdesk.domain.access import ExecutionReceipt
from aegisdesk.domain.enums import AccessDuration, Permission
from aegisdesk.domain.errors import ProtectedExecutionError
from aegisdesk.domain.ids import ActionId, EmployeeId, ResourceId

AT = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)
ACTION = ActionId("ACT-0001")


def receipt(**overrides: Any) -> ExecutionReceipt:
    fields: dict[str, Any] = {
        "action_id": ACTION,
        "requester_id": EmployeeId("E1042"),
        "resource_id": ResourceId("jira"),
        "permission": Permission.READ,
        "duration": AccessDuration.ONE_HOUR,
        "authorised_at": AT,
    }
    fields.update(overrides)
    return ExecutionReceipt(**fields)


def backend_and_key() -> tuple[AccessBackend, str]:
    backend = AccessBackend()
    return backend, backend.claim_minting_authority()


def test_a_grant_records_the_action_that_authorised_it() -> None:
    backend, key = backend_and_key()
    grant = backend.grant(receipt(), key)
    assert grant.granted_via_action_id == ACTION
    assert grant.employee_id == EmployeeId("E1042")


@pytest.mark.parametrize(
    ("duration", "expected"),
    [
        (AccessDuration.ONE_HOUR, AT + timedelta(hours=1)),
        (AccessDuration.EIGHT_HOURS, AT + timedelta(hours=8)),
        (AccessDuration.PERMANENT, None),
    ],
)
def test_expiry_is_derived_from_the_duration(
    duration: AccessDuration, expected: datetime | None
) -> None:
    backend, key = backend_and_key()
    grant = backend.grant(receipt(duration=duration), key)
    assert grant.expires_at == expected


def test_a_repeated_execution_returns_the_grant_that_exists() -> None:
    # Deterministic idempotency at one boundary: a retried execution of one authorised action
    # returns what is already there rather than issuing a second grant.
    backend, key = backend_and_key()
    first = backend.grant(receipt(), key)
    second = backend.grant(receipt(), key)
    assert second is first
    assert backend.grant_for(ACTION) is first


def test_a_repeated_execution_ignores_altered_fields_under_one_action_id() -> None:
    # The identifier is derived from the action, so two receipts sharing one identifier
    # describe one action. A second call carrying different values is a retry to be absorbed,
    # not a new grant to be written.
    backend, key = backend_and_key()
    first = backend.grant(receipt(), key)
    second = backend.grant(receipt(permission=Permission.ADMIN), key)
    assert second is first
    assert second.permission is Permission.READ


def test_a_distinct_action_writes_its_own_grant() -> None:
    backend, key = backend_and_key()
    first = backend.grant(receipt(), key)
    second = backend.grant(receipt(action_id=ActionId("ACT-0002")), key)
    assert second is not first
    assert backend.grant_for(ActionId("ACT-0002")) is second


@pytest.mark.parametrize(
    "argument",
    [
        None,
        "ACT-0001",
        {"action_id": "ACT-0001", "requester_id": "E1042"},
        object(),
    ],
)
def test_the_backend_refuses_anything_that_is_not_a_receipt(argument: Any) -> None:
    backend, key = backend_and_key()
    with pytest.raises(ProtectedExecutionError):
        backend.grant(argument, key)


def test_the_backend_has_no_entry_point_taking_loose_identifiers() -> None:
    # A caller that skipped the guard has nothing to pass: there is no signature accepting an
    # employee and a resource directly.
    public = {name for name in dir(AccessBackend) if not name.startswith("_")}
    assert public == {"grant", "grant_for", "claim_minting_authority"}


def test_an_unknown_action_has_no_grant() -> None:
    assert AccessBackend().grant_for(ActionId("ACT-9999")) is None


# --- a receipt is unusable without the minting key ------------------------------------------


@pytest.mark.parametrize("forged", ["", "minting-key", "x" * 43, "ké", None, 1, object()])
def test_a_caller_built_receipt_cannot_execute(forged: Any) -> None:
    # The receipt class is importable, so a caller can construct one. Without the key the
    # backend issued to its one minting authority, the constructed receipt does nothing.
    backend, _ = backend_and_key()
    with pytest.raises(ProtectedExecutionError):
        backend.grant(receipt(), forged)
    assert backend.grant_for(ACTION) is None


def test_the_authority_can_be_claimed_only_once() -> None:
    backend = AccessBackend()
    backend.claim_minting_authority()
    with pytest.raises(ProtectedExecutionError):
        backend.claim_minting_authority()


def test_a_key_from_another_backend_does_not_transfer() -> None:
    backend, _ = backend_and_key()
    _, other_key = backend_and_key()
    with pytest.raises(ProtectedExecutionError):
        backend.grant(receipt(), other_key)


def test_a_missing_receipt_and_an_unminted_one_are_indistinguishable() -> None:
    backend, key = backend_and_key()
    absent_receipt: Any = None
    with pytest.raises(ProtectedExecutionError) as absent:
        backend.grant(absent_receipt, key)
    with pytest.raises(ProtectedExecutionError) as unminted:
        backend.grant(receipt(), "not-the-key")
    assert str(absent.value) == str(unminted.value)


def test_the_key_is_not_reachable_by_importing_anything() -> None:
    # Generated per instance, so two backends do not share it and no module attribute holds
    # it. This is the property that makes a constructed receipt useless.
    first, first_key = backend_and_key()
    second, second_key = backend_and_key()
    assert first_key != second_key
    with pytest.raises(ProtectedExecutionError):
        second.grant(receipt(), first_key)
