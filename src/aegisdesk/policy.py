from typing import Final, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, model_validator

from aegisdesk.domain.employee import Employee
from aegisdesk.domain.enums import (
    PERMISSION_RANK,
    AccessDuration,
    Permission,
    PolicyEffect,
    PolicyReason,
    ProtectedOperation,
    ResourceClass,
    RiskTier,
)
from aegisdesk.domain.errors import DomainInvariantError
from aegisdesk.domain.ids import ActionId, EmployeeId, PolicyVersion, ResourceId, WorkflowId
from aegisdesk.domain.resource import Resource

# Bump whenever the rule sequence below changes. An approval record stores the version that
# was in force when the decision was made, and a resuming workflow compares it, so editing a
# rule without bumping this would let a decision reached under the old rules authorise
# execution under the new ones.
POLICY_VERSION: Final[PolicyVersion] = PolicyVersion("1")


class PolicyRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Trusted runtime context. Identity travels here rather than in anything a model wrote
    # (DESIGN.md AD-2), and the action identifier is derived deterministically by the runtime
    # so it survives a pause and resume (AD-4). The engine reads no clock: the caller stamps
    # the instant it evaluated at, which is what keeps evaluation pure.
    workflow_id: WorkflowId
    action_id: ActionId
    evaluated_at: AwareDatetime

    # Which protected operation is being evaluated. Grant resolves within baseline; revoke and
    # modify never resolve automatically. The engine reads it rather than inferring intent from
    # the other fields.
    operation: ProtectedOperation
    requester: Employee
    # None when the requested identifier did not resolve to a catalogue entry. Resolving it
    # belongs to the caller because a lookup is I/O.
    resource: Resource | None
    permission: Permission
    # Present for a grant, absent for the destructive operations, which have no duration.
    duration: AccessDuration | None

    # Authoritative baseline access for this requester on this resource, read from the
    # directory (project.md 10.3 lists "baseline access" as authoritative employee context),
    # never computed here. None means the requester holds no baseline access to it.
    # project.md states no baseline value anywhere, so the engine compares what it is handed
    # and declares none of its own.
    baseline_permission: Permission | None
    # Supplied for the same reason. project.md 9 requires the policy to define risk tiers and
    # 9.1 requires the tier on the decision, but no section states a mapping from anything to
    # a tier. It is recorded and never consulted, so a wrong tier cannot alter authorisation.
    # It must come from trusted configuration; a tier a model chose would reach a reviewer.
    risk_tier: RiskTier

    @model_validator(mode="after")
    def _duration_matches_operation(self) -> Self:
        is_grant = self.operation is ProtectedOperation.GRANT_ACCESS
        if is_grant and self.duration is None:
            raise DomainInvariantError("a grant request must carry a duration")
        if not is_grant and self.duration is not None:
            raise DomainInvariantError(
                f"a {self.operation.value} request must not carry a duration"
            )
        return self


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_version: PolicyVersion
    effect: PolicyEffect
    reason: PolicyReason
    # The requested operation (project.md 9.1 lists the requested action on the decision). Absent
    # only for an EVALUATION_ERROR, which could not read the request at all.
    operation: ProtectedOperation | None

    # project.md 9.1 enumerates what an auditable decision object contains: policy version,
    # requester, resource, requested action, risk tier, decision, reason, timestamp, and
    # workflow/action ID. Every field below carries one of them.
    #
    # They are absent together exactly when the reason is EVALUATION_ERROR: the request could
    # not be read, and copying unvalidated values into a record bound for the audit trail
    # would put untrusted data where authoritative data belongs. resource_id is additionally
    # absent for UNKNOWN_RESOURCE, which is the one readable case with nothing to name.
    workflow_id: WorkflowId | None
    action_id: ActionId | None
    evaluated_at: AwareDatetime | None
    requester_id: EmployeeId | None
    resource_id: ResourceId | None
    permission: Permission | None
    duration: AccessDuration | None
    risk_tier: RiskTier | None

    @model_validator(mode="after")
    def _record_agrees_with_reason(self) -> Self:
        # duration is required only for a grant: a revoke or a modify is a readable decision that
        # legitimately carries none, so it is checked against the operation rather than listed
        # among the always-required fields.
        required = (
            self.workflow_id,
            self.action_id,
            self.evaluated_at,
            self.operation,
            self.requester_id,
            self.permission,
            self.risk_tier,
        )
        if self.reason is PolicyReason.EVALUATION_ERROR:
            echoed = (*required, self.resource_id, self.duration)
            if any(field is not None for field in echoed):
                raise DomainInvariantError("an EVALUATION_ERROR decision must not echo its request")
            return self
        if any(field is None for field in required):
            raise DomainInvariantError("a readable decision must carry every required field")
        is_grant = self.operation is ProtectedOperation.GRANT_ACCESS
        if is_grant and self.duration is None:
            raise DomainInvariantError("a readable grant decision must carry a duration")
        if not is_grant and self.duration is not None:
            raise DomainInvariantError("a destructive decision must not carry a duration")
        return self


_UNREADABLE_REQUEST: Final[PolicyDecision] = PolicyDecision(
    policy_version=POLICY_VERSION,
    effect=PolicyEffect.DENY,
    reason=PolicyReason.EVALUATION_ERROR,
    operation=None,
    workflow_id=None,
    action_id=None,
    evaluated_at=None,
    requester_id=None,
    resource_id=None,
    permission=None,
    duration=None,
    risk_tier=None,
)


# Decides a single access request. Pure: no I/O, no clock, no state.
#
# The engine trusts the records it is handed. A caller that builds a Resource itself rather
# than reading the catalogue can misclassify one, and a caller that supplies a baseline the
# directory did not issue can widen what is automatic, so the runtime guard has to resolve
# both rather than accept them from whatever proposed the action.
def evaluate(request: PolicyRequest) -> PolicyDecision:
    # Constructing a PolicyRequest is the checked boundary: it rejects an unknown enum value,
    # a naive timestamp, and an object that merely looks like an Employee or a Resource. What
    # is left to check here is whether a PolicyRequest arrived at all.
    if not isinstance(request, PolicyRequest):
        return _UNREADABLE_REQUEST

    effect, reason = _classify(request)
    return _decide(effect, reason, request)


# Order is the policy, written as one linear sequence so the precedence can be read off the
# page. Every denial is decided before any escalation, so a request tripping a deny rule is
# refused outright instead of being put in front of a reviewer who could approve what policy
# already refused.
#
# PolicyReason.DEPARTMENT_MISMATCH is deliberately unreachable. Resource.owning_department
# exists, but project.md states nowhere what happens when a requester sits outside a
# resource's owning department: section 6 lists "department-specific access" as a supported
# request category, section 9 lists both "escalation conditions" and "prohibited operations"
# without placing it in either, and 13.7 permits "escalates or refuses". Departmental scope
# therefore reaches the engine through the authoritative baseline it is given, which is where
# 10.3 puts it, and the engine takes no position of its own. The reason stays reserved.
def _classify(request: PolicyRequest) -> tuple[PolicyEffect, PolicyReason]:
    resource = request.resource
    if resource is None:
        return PolicyEffect.DENY, PolicyReason.UNKNOWN_RESOURCE

    if not request.requester.is_active:
        return PolicyEffect.DENY, PolicyReason.REQUESTER_INACTIVE

    # Destructive operations never resolve automatically. A revoke or a modify always reaches a
    # human, whatever baseline the requester holds, so it is decided here — after the deny checks
    # above, which still apply — before the grant-only baseline logic below. No narrowing or
    # reversible case is auto-allowed in S10 (decision 7).
    if request.operation is ProtectedOperation.REVOKE_ACCESS:
        return PolicyEffect.REQUIRE_APPROVAL, PolicyReason.REVOKE_REQUIRES_APPROVAL
    if request.operation is ProtectedOperation.MODIFY_PERMISSIONS:
        return PolicyEffect.REQUIRE_APPROVAL, PolicyReason.MODIFY_REQUIRES_APPROVAL

    # The one place the engine overrides its input: privileged access never resolves
    # automatically, whatever baseline it was handed. project.md 9.1 works exactly this case
    # through — engineer, prod-db, admin, permanent, REQUIRE_HUMAN_APPROVAL — and 8.3 gives
    # privileged and production access to the Escalation agent.
    if resource.resource_class is ResourceClass.PRIVILEGED:
        # Standing access is the more specific finding, so it is reported ahead of the
        # resource class it also implies.
        if request.duration is AccessDuration.PERMANENT:
            return PolicyEffect.REQUIRE_APPROVAL, PolicyReason.STANDING_PRIVILEGED_ACCESS
        return PolicyEffect.REQUIRE_APPROVAL, PolicyReason.PRIVILEGED_RESOURCE

    baseline = request.baseline_permission
    if baseline is None or PERMISSION_RANK[request.permission] > PERMISSION_RANK[baseline]:
        return PolicyEffect.REQUIRE_APPROVAL, PolicyReason.EXCEEDS_BASELINE_PERMISSION

    return PolicyEffect.ALLOW, PolicyReason.WITHIN_BASELINE


def _decide(effect: PolicyEffect, reason: PolicyReason, request: PolicyRequest) -> PolicyDecision:
    resource = request.resource
    return PolicyDecision(
        policy_version=POLICY_VERSION,
        effect=effect,
        reason=reason,
        operation=request.operation,
        workflow_id=request.workflow_id,
        action_id=request.action_id,
        evaluated_at=request.evaluated_at,
        requester_id=request.requester.employee_id,
        resource_id=resource.resource_id if resource is not None else None,
        permission=request.permission,
        duration=request.duration,
        risk_tier=request.risk_tier,
    )
