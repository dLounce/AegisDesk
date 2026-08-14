import hashlib
from collections.abc import Mapping
from typing import Final, Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator

from aegisdesk.domain.enums import AccessDuration, Permission, ProtectedOperation
from aegisdesk.domain.errors import DomainInvariantError
from aegisdesk.domain.ids import (
    ActionId,
    ArgumentDigest,
    EmployeeId,
    PolicyVersion,
    ResourceId,
    TicketId,
    WorkflowId,
)


# What a model may name, shared by every protected operation. Identity, the resource record,
# baseline access, the risk tier, reversibility, the action identifier and the policy decision
# are absent by design: the guard resolves each from an authoritative source. There is no field
# naming an employee, so acting on somebody else's access is not expressible rather than merely
# refused (DESIGN.md AD-2). Each operation is its own subclass, so the fields that are
# semantically applicable to it are the only ones it carries — a revoke has no field a duration
# could arrive in (S10 decision 4).
class ProtectedActionProposal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: ProtectedOperation
    resource_id: ResourceId
    permission: Permission
    ticket_id: TicketId


# A grant. Keeps the exact shape the earlier milestones pinned, including the duration a grant is
# time-boxed by, so the golden action and digest vectors are unchanged.
class ProposedAction(ProtectedActionProposal):
    operation: Literal[ProtectedOperation.GRANT_ACCESS] = ProtectedOperation.GRANT_ACCESS
    duration: AccessDuration


# A revocation of a named permission. No duration: revoking removes the permission rather than
# issuing a bounded one.
class RevokeAccessProposal(ProtectedActionProposal):
    operation: Literal[ProtectedOperation.REVOKE_ACCESS] = ProtectedOperation.REVOKE_ACCESS


# A change of an existing permission to a target permission. No duration in S10.
class ModifyPermissionsProposal(ProtectedActionProposal):
    operation: Literal[ProtectedOperation.MODIFY_PERMISSIONS] = (
        ProtectedOperation.MODIFY_PERMISSIONS
    )


# The same action after the guard has resolved each value against an authoritative source: the
# requester from the session and the directory, the resource from the catalogue, the ticket
# from the store, the workflow from the runtime. That is what makes the canonical form below
# safe to build by concatenation — no value on this record is a string a model chose, so none
# can carry a separator and forge a neighbouring field. duration is present for a grant and
# absent for the destructive operations, which have no duration to bind.
class ResolvedAction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: ProtectedOperation
    requester_id: EmployeeId
    resource_id: ResourceId
    permission: Permission
    duration: AccessDuration | None
    ticket_id: TicketId
    workflow_id: WorkflowId

    @model_validator(mode="after")
    def _duration_matches_operation(self) -> Self:
        is_grant = self.operation is ProtectedOperation.GRANT_ACCESS
        if is_grant and self.duration is None:
            raise DomainInvariantError("a grant must carry a duration")
        if not is_grant and self.duration is not None:
            raise DomainInvariantError(f"{self.operation.value} must not carry a duration")
        return self


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


# duration appears only for a grant. Omitting the key rather than writing a sentinel keeps the
# grant form byte-identical to earlier milestones while giving a revoke or a modify a distinct
# canonical form — and therefore a distinct identity — from a grant and from each other.
def _action_fields(action: ResolvedAction) -> dict[str, str]:
    fields = {
        "operation": action.operation.value,
        "permission": action.permission.value,
        "requester_id": action.requester_id,
        "resource_id": action.resource_id,
        "ticket_id": action.ticket_id,
        "workflow_id": action.workflow_id,
    }
    if action.duration is not None:
        fields["duration"] = action.duration.value
    return fields


def canonical_action_form(action: ResolvedAction) -> bytes:
    return _canonical(_ACTION_DOMAIN, _action_fields(action))


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
    fields = _action_fields(action)
    fields["action_id"] = action_id
    fields["policy_version"] = policy_version
    return _canonical(_DIGEST_DOMAIN, fields)


# Covers the whole effect-determining tuple plus the policy version in force when the decision
# was reached. An approval binds to this value, so changing any field between approval and
# execution — including editing a policy rule — invalidates the binding (DESIGN.md AD-3).
def compute_argument_digest(
    action: ResolvedAction, action_id: ActionId, policy_version: PolicyVersion
) -> ArgumentDigest:
    form = canonical_digest_form(action, action_id, policy_version)
    return ArgumentDigest(hashlib.sha256(form).hexdigest())
