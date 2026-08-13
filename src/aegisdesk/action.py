import hashlib
from collections.abc import Mapping
from typing import Final

from pydantic import BaseModel, ConfigDict

from aegisdesk.domain.enums import AccessDuration, Permission, ProtectedOperation
from aegisdesk.domain.ids import (
    ActionId,
    ArgumentDigest,
    EmployeeId,
    PolicyVersion,
    ResourceId,
    TicketId,
    WorkflowId,
)


# What a model may name. Identity, the resource record, baseline access, the risk tier, the
# action identifier and the policy decision are absent by design: the guard resolves each from
# an authoritative source. There is no field naming an employee, so a grant to somebody else
# is not expressible rather than merely refused (DESIGN.md AD-2).
class ProposedAction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: ProtectedOperation
    resource_id: ResourceId
    permission: Permission
    duration: AccessDuration
    ticket_id: TicketId


# The same action after the guard has resolved each value against an authoritative source: the
# requester from the session and the directory, the resource from the catalogue, the ticket
# from the store, the workflow from the runtime. That is what makes the canonical form below
# safe to build by concatenation — no value on this record is a string a model chose, so none
# can carry a separator and forge a neighbouring field.
class ResolvedAction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: ProtectedOperation
    requester_id: EmployeeId
    resource_id: ResourceId
    permission: Permission
    duration: AccessDuration
    ticket_id: TicketId
    workflow_id: WorkflowId


# Domain separation, so a byte string produced for one purpose cannot be replayed as the other
# even if the field sets ever coincide. The version suffix makes a future change to the
# canonical form a different value rather than a silent re-binding of existing approvals.
_ACTION_DOMAIN: Final = b"aegisdesk.action.v1"
_DIGEST_DOMAIN: Final = b"aegisdesk.digest.v1"

# The identifier is read by a reviewer and written into audit lines, so it is shortened. 128
# bits of a domain-separated SHA-256 leaves collision infeasible at any scale this system
# reaches, and a collision would in any case require two actions agreeing on every field below.
ACTION_ID_HEX_LENGTH: Final = 32


def _canonical(domain: bytes, fields: Mapping[str, str]) -> bytes:
    body = "\n".join(f"{name}={fields[name]}" for name in sorted(fields))
    return domain + b"\n" + body.encode("utf-8")


def canonical_action_form(action: ResolvedAction) -> bytes:
    return _canonical(
        _ACTION_DOMAIN,
        {
            "duration": action.duration.value,
            "operation": action.operation.value,
            "permission": action.permission.value,
            "requester_id": action.requester_id,
            "resource_id": action.resource_id,
            "ticket_id": action.ticket_id,
            "workflow_id": action.workflow_id,
        },
    )


# Derived rather than generated, so the proposing pass and the resuming pass agree without
# either persisting a random value (DESIGN.md AD-4). policy_version is deliberately absent:
# a rule change must show up as a digest mismatch that can be reported, not as a lookup that
# quietly finds nothing.
def derive_action_id(action: ResolvedAction) -> ActionId:
    digest = hashlib.sha256(canonical_action_form(action)).hexdigest()
    return ActionId(f"ACT-{digest[:ACTION_ID_HEX_LENGTH]}")


def canonical_digest_form(
    action: ResolvedAction, action_id: ActionId, policy_version: PolicyVersion
) -> bytes:
    return _canonical(
        _DIGEST_DOMAIN,
        {
            "action_id": action_id,
            "duration": action.duration.value,
            "operation": action.operation.value,
            "permission": action.permission.value,
            "policy_version": policy_version,
            "requester_id": action.requester_id,
            "resource_id": action.resource_id,
            "ticket_id": action.ticket_id,
            "workflow_id": action.workflow_id,
        },
    )


# Covers the whole effect-determining tuple plus the policy version in force when the decision
# was reached. An approval binds to this value, so changing any field between approval and
# execution — including editing a policy rule — invalidates the binding (DESIGN.md AD-3).
def compute_argument_digest(
    action: ResolvedAction, action_id: ActionId, policy_version: PolicyVersion
) -> ArgumentDigest:
    form = canonical_digest_form(action, action_id, policy_version)
    return ArgumentDigest(hashlib.sha256(form).hexdigest())
