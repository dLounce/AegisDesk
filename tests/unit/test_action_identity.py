from typing import Any

import pytest
from pydantic import ValidationError

from aegisdesk.action import (
    ProposedAction,
    ResolvedAction,
    canonical_action_form,
    canonical_digest_form,
    compute_argument_digest,
    derive_action_id,
)
from aegisdesk.domain.enums import AccessDuration, Permission, ProtectedOperation
from aegisdesk.domain.ids import (
    ActionId,
    EmployeeId,
    PolicyVersion,
    ResourceId,
    TicketId,
    WorkflowId,
)

VERSION = PolicyVersion("1")

GOLDEN_ACTION_FORM = (
    b"aegisdesk.action.v1\n"
    b"duration=permanent\n"
    b"operation=grant_access\n"
    b"permission=admin\n"
    b"requester_id=E1042\n"
    b"resource_id=prod-db\n"
    b"ticket_id=IT-0001\n"
    b"workflow_id=WF-0001"
)
GOLDEN_ACTION_ID = ActionId("ACT-4e3754803774276ec61c3a5347793aca")
GOLDEN_DIGEST_FORM = (
    b"aegisdesk.digest.v1\n"
    b"action_id=ACT-4e3754803774276ec61c3a5347793aca\n"
    b"duration=permanent\n"
    b"operation=grant_access\n"
    b"permission=admin\n"
    b"policy_version=1\n"
    b"requester_id=E1042\n"
    b"resource_id=prod-db\n"
    b"ticket_id=IT-0001\n"
    b"workflow_id=WF-0001"
)
GOLDEN_DIGEST = "bf2607d6efbd319847ccfe57c3201bc06cb691e8d32b34a2c9501722d42f0e9d"


def resolved(**overrides: Any) -> ResolvedAction:
    fields: dict[str, Any] = {
        "operation": ProtectedOperation.GRANT_ACCESS,
        "requester_id": EmployeeId("E1042"),
        "resource_id": ResourceId("prod-db"),
        "permission": Permission.ADMIN,
        "duration": AccessDuration.PERMANENT,
        "ticket_id": TicketId("IT-0001"),
        "workflow_id": WorkflowId("WF-0001"),
    }
    fields.update(overrides)
    return ResolvedAction(**fields)


# --- the proposal record is the model-facing boundary ---------------------------------------


def test_a_proposal_declares_exactly_the_five_permitted_fields() -> None:
    assert set(ProposedAction.model_fields) == {
        "operation",
        "resource_id",
        "permission",
        "duration",
        "ticket_id",
    }


@pytest.mark.parametrize(
    "field",
    ["requester_id", "employee_id", "baseline_permission", "risk_tier", "action_id", "resource"],
)
def test_a_proposal_refuses_a_field_the_guard_owns(field: str) -> None:
    with pytest.raises(ValidationError):
        ProposedAction(
            operation=ProtectedOperation.GRANT_ACCESS,
            resource_id=ResourceId("prod-db"),
            permission=Permission.ADMIN,
            duration=AccessDuration.PERMANENT,
            ticket_id=TicketId("IT-0001"),
            **{field: "anything"},
        )


def test_a_proposal_refuses_an_unknown_enum_value() -> None:
    with pytest.raises(ValidationError):
        ProposedAction(
            operation=ProtectedOperation.GRANT_ACCESS,
            resource_id=ResourceId("prod-db"),
            permission="superuser",  # type: ignore[arg-type]
            duration=AccessDuration.PERMANENT,
            ticket_id=TicketId("IT-0001"),
        )


def test_a_proposal_is_frozen() -> None:
    action = ProposedAction(
        operation=ProtectedOperation.GRANT_ACCESS,
        resource_id=ResourceId("prod-db"),
        permission=Permission.ADMIN,
        duration=AccessDuration.PERMANENT,
        ticket_id=TicketId("IT-0001"),
    )
    with pytest.raises(ValidationError):
        action.permission = Permission.READ


def test_the_resolved_record_is_frozen_and_closed() -> None:
    action = resolved()
    with pytest.raises(ValidationError):
        action.permission = Permission.READ
    with pytest.raises(ValidationError):
        resolved(risk_tier="low")


# --- golden vectors --------------------------------------------------------------------------


def test_the_canonical_action_form_is_pinned() -> None:
    # Pinned to the byte, so a change to the serialisation is a visible failure rather than a
    # silent re-binding of approvals issued under the old form.
    assert canonical_action_form(resolved()) == GOLDEN_ACTION_FORM


def test_the_action_identifier_is_pinned() -> None:
    assert derive_action_id(resolved()) == GOLDEN_ACTION_ID


def test_the_canonical_digest_form_is_pinned() -> None:
    assert canonical_digest_form(resolved(), GOLDEN_ACTION_ID, VERSION) == GOLDEN_DIGEST_FORM


def test_the_argument_digest_is_pinned() -> None:
    assert compute_argument_digest(resolved(), GOLDEN_ACTION_ID, VERSION) == GOLDEN_DIGEST


def test_the_identifier_is_derived_rather_than_generated() -> None:
    # The proposing pass and a resuming pass have to agree without persisting a random value.
    assert derive_action_id(resolved()) == derive_action_id(resolved())


# --- what each value binds -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requester_id", EmployeeId("E1043")),
        ("resource_id", ResourceId("prod-k8s")),
        ("permission", Permission.READ),
        ("duration", AccessDuration.ONE_HOUR),
        ("ticket_id", TicketId("IT-0002")),
        ("workflow_id", WorkflowId("WF-0002")),
    ],
)
def test_altering_a_covered_field_alters_the_identifier(field: str, value: Any) -> None:
    assert derive_action_id(resolved(**{field: value})) != GOLDEN_ACTION_ID


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requester_id", EmployeeId("E1043")),
        ("resource_id", ResourceId("prod-k8s")),
        ("permission", Permission.READ),
        ("duration", AccessDuration.ONE_HOUR),
        ("ticket_id", TicketId("IT-0002")),
        ("workflow_id", WorkflowId("WF-0002")),
    ],
)
def test_altering_a_covered_field_alters_the_digest(field: str, value: Any) -> None:
    altered = resolved(**{field: value})
    assert compute_argument_digest(altered, derive_action_id(altered), VERSION) != GOLDEN_DIGEST


def test_the_policy_version_binds_the_digest_and_not_the_identifier() -> None:
    # A rule change must show up as a mismatch that can be reported, rather than as a lookup
    # that quietly finds nothing.
    assert derive_action_id(resolved()) == GOLDEN_ACTION_ID
    under_v2 = compute_argument_digest(resolved(), GOLDEN_ACTION_ID, PolicyVersion("2"))
    assert under_v2 != GOLDEN_DIGEST


def test_the_identifier_binds_the_digest() -> None:
    other = ActionId("ACT-00000000000000000000000000000000")
    assert compute_argument_digest(resolved(), other, VERSION) != GOLDEN_DIGEST


def test_the_two_domains_do_not_collide() -> None:
    # Domain separation, so a byte string produced for one purpose cannot be replayed as the
    # other even if the field sets ever coincide.
    assert canonical_action_form(resolved()) != canonical_digest_form(
        resolved(), GOLDEN_ACTION_ID, VERSION
    )


def test_a_separator_cannot_be_smuggled_through_a_resolved_value() -> None:
    # Every value on a ResolvedAction came from the session, the catalogue, the ticket store or
    # the runtime, so this case does not arise through the guard. Pinned anyway: a value that
    # did carry a separator produces a different digest rather than one matching a forged field
    # arrangement.
    smuggled = resolved(resource_id=ResourceId("wiki\npermission=admin"))
    honest = resolved(resource_id=ResourceId("wiki"), permission=Permission.ADMIN)
    assert derive_action_id(smuggled) != derive_action_id(honest)
