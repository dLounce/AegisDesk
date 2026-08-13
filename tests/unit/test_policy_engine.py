from datetime import UTC, datetime
from itertools import product
from typing import Any

import pytest
from pydantic import ValidationError

from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.seed import load_baseline_access, load_employees, load_resources
from aegisdesk.domain.employee import Employee
from aegisdesk.domain.enums import (
    PERMISSION_RANK,
    AccessDuration,
    Department,
    EmployeeRole,
    Permission,
    PolicyEffect,
    PolicyReason,
    ResourceClass,
    RiskTier,
)
from aegisdesk.domain.ids import ActionId, EmployeeId, ResourceId, WorkflowId
from aegisdesk.domain.resource import Resource
from aegisdesk.policy import (
    POLICY_VERSION,
    PolicyDecision,
    PolicyRequest,
    evaluate,
)

WORKFLOW = WorkflowId("WF-0001")
ACTION = ActionId("ACT-0001")
AT = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)


def employee(
    role: EmployeeRole = EmployeeRole.INDIVIDUAL_CONTRIBUTOR,
    department: Department = Department.ENGINEERING,
    is_active: bool = True,
) -> Employee:
    return Employee(
        employee_id=EmployeeId("E1042"),
        display_name="Priya Raghunathan",
        department=department,
        role=role,
        manager_id=None,
        is_active=is_active,
    )


def resource(
    resource_class: ResourceClass = ResourceClass.BASELINE,
    owning_department: Department | None = None,
) -> Resource:
    return Resource(
        resource_id=ResourceId("wiki"),
        display_name="Company Wiki",
        resource_class=resource_class,
        owning_department=owning_department,
    )


def request(**overrides: Any) -> PolicyRequest:
    fields: dict[str, Any] = {
        "workflow_id": WORKFLOW,
        "action_id": ACTION,
        "evaluated_at": AT,
        "requester": employee(),
        "resource": resource(),
        "permission": Permission.READ,
        "duration": AccessDuration.ONE_HOUR,
        "baseline_permission": Permission.WRITE,
        "risk_tier": RiskTier.LOW,
    }
    fields.update(overrides)
    return PolicyRequest(**fields)


# --- the request record is the trust boundary --------------------------------------------


def test_request_record_is_frozen_and_closed() -> None:
    built = request()
    with pytest.raises(ValidationError):
        built.permission = Permission.ADMIN
    with pytest.raises(ValidationError):
        request(approved=True)


def test_request_record_rejects_a_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        request(evaluated_at=datetime(2026, 8, 13, 9, 0))


def test_request_record_rejects_an_unknown_enum_value() -> None:
    with pytest.raises(ValidationError):
        request(permission="superuser")
    with pytest.raises(ValidationError):
        request(risk_tier="apocalyptic")


def test_request_record_converts_a_known_enum_value_at_the_boundary() -> None:
    # A string naming a real member is converted here, and this is the only place that
    # conversion is allowed to happen: it raises on anything unknown, so it is a checked
    # entry point rather than a coercion the engine performs on a caller's behalf.
    assert request(permission="admin").permission is Permission.ADMIN


def test_request_record_refuses_an_object_that_merely_looks_like_a_requester() -> None:
    class LookAlike:
        employee_id = EmployeeId("E1042")
        department = Department.ENGINEERING
        role = EmployeeRole.EXECUTIVE
        is_active = True

    with pytest.raises(ValidationError):
        request(requester=LookAlike())


def test_request_record_refuses_an_object_that_merely_looks_like_a_resource() -> None:
    class LookAlike:
        resource_id = ResourceId("wiki")
        resource_class = ResourceClass.BASELINE
        owning_department = None

    with pytest.raises(ValidationError):
        request(resource=LookAlike())


# --- baseline access is supplied, never computed ------------------------------------------


def test_baseline_is_supplied_by_the_caller_not_derived_from_role() -> None:
    # Two requests alike in every respect except the baseline the directory reported. The
    # engine holds no table that could disagree with it.
    permissive = evaluate(
        request(permission=Permission.WRITE, baseline_permission=Permission.WRITE)
    )
    restrictive = evaluate(
        request(permission=Permission.WRITE, baseline_permission=Permission.READ)
    )
    assert permissive.effect is PolicyEffect.ALLOW
    assert permissive.reason is PolicyReason.WITHIN_BASELINE
    assert restrictive.effect is PolicyEffect.REQUIRE_APPROVAL
    assert restrictive.reason is PolicyReason.EXCEEDS_BASELINE_PERMISSION


def test_baseline_is_supplied_no_baseline_means_no_automatic_access() -> None:
    decision = evaluate(request(permission=Permission.READ, baseline_permission=None))
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.reason is PolicyReason.EXCEEDS_BASELINE_PERMISSION


@pytest.mark.parametrize("role", list(EmployeeRole))
def test_baseline_is_supplied_the_role_does_not_change_the_outcome(role: EmployeeRole) -> None:
    # project.md states no baseline value for any role, so the engine must not read the role
    # at all. Identical baselines across every role must produce identical decisions.
    decision = evaluate(request(requester=employee(role=role)))
    assert decision.effect is PolicyEffect.ALLOW


def test_baseline_is_supplied_admin_is_allowed_when_the_directory_says_so() -> None:
    # There is no rule here that admin can never be baseline. project.md never says that, so
    # a directory reporting admin baseline on a non-privileged resource is honoured.
    decision = evaluate(request(permission=Permission.ADMIN, baseline_permission=Permission.ADMIN))
    assert decision.effect is PolicyEffect.ALLOW


# --- risk tier is carried, never consulted ------------------------------------------------


@pytest.mark.parametrize("tier", list(RiskTier))
def test_risk_is_carried_through_to_the_decision(tier: RiskTier) -> None:
    assert evaluate(request(risk_tier=tier)).risk_tier is tier


@pytest.mark.parametrize("tier", list(RiskTier))
def test_forged_risk_tier_cannot_alter_an_allowed_decision(tier: RiskTier) -> None:
    # The tier reaches a reviewer's screen and an audit record, so a wrong or hostile value
    # must be inert. Substituting any tier leaves both effect and reason untouched.
    decision = evaluate(request(risk_tier=tier))
    assert decision.effect is PolicyEffect.ALLOW
    assert decision.reason is PolicyReason.WITHIN_BASELINE


@pytest.mark.parametrize("tier", list(RiskTier))
def test_forged_risk_tier_cannot_alter_a_refused_decision(tier: RiskTier) -> None:
    decision = evaluate(request(resource=resource(ResourceClass.PRIVILEGED), risk_tier=tier))
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.reason is PolicyReason.PRIVILEGED_RESOURCE


# --- the department reason is reserved, not implemented -----------------------------------


def test_department_reason_is_reserved_and_unreachable() -> None:
    # project.md does not state what happens when a requester sits outside a resource's
    # owning department, so the engine takes no position. Departmental scope reaches it
    # through the supplied baseline instead. If a rule is ever added, this fails and forces
    # the decision to be made deliberately.
    combinations = product(
        Department,
        (True, False),
        ResourceClass,
        (None, *Department),
        Permission,
        AccessDuration,
        (None, *Permission),
    )
    reasons: set[PolicyReason] = set()
    for dept, active, rclass, owner, permission, duration, baseline in combinations:
        reasons.add(
            evaluate(
                request(
                    requester=employee(department=dept, is_active=active),
                    resource=resource(rclass, owner),
                    permission=permission,
                    duration=duration,
                    baseline_permission=baseline,
                )
            ).reason
        )
    assert PolicyReason.DEPARTMENT_MISMATCH not in reasons


def test_an_out_of_department_resource_is_decided_by_the_supplied_baseline() -> None:
    # Stated explicitly so the behaviour is visible rather than incidental: with a baseline
    # supplied, a resource owned by another department is not treated specially.
    decision = evaluate(
        request(
            requester=employee(department=Department.FINANCE),
            resource=resource(ResourceClass.SENSITIVE, Department.HR),
            baseline_permission=Permission.READ,
        )
    )
    assert decision.effect is PolicyEffect.ALLOW


# --- section 9.1 required fields ----------------------------------------------------------


def test_nine_required_fields_are_present_on_a_decision() -> None:
    decision = evaluate(request(permission=Permission.WRITE, duration=AccessDuration.EIGHT_HOURS))
    assert decision.policy_version == POLICY_VERSION
    assert decision.requester_id == EmployeeId("E1042")
    assert decision.resource_id == ResourceId("wiki")
    assert decision.permission is Permission.WRITE
    assert decision.duration is AccessDuration.EIGHT_HOURS
    assert decision.risk_tier is RiskTier.LOW
    assert decision.effect is PolicyEffect.ALLOW
    assert decision.reason is PolicyReason.WITHIN_BASELINE
    assert decision.evaluated_at == AT
    assert decision.workflow_id == WORKFLOW
    assert decision.action_id == ACTION


def test_nine_required_fields_survive_a_refusal() -> None:
    decision = evaluate(request(resource=resource(ResourceClass.PRIVILEGED)))
    for field in (
        decision.policy_version,
        decision.requester_id,
        decision.resource_id,
        decision.permission,
        decision.duration,
        decision.risk_tier,
        decision.evaluated_at,
        decision.workflow_id,
        decision.action_id,
    ):
        assert field is not None


def test_the_timestamp_is_the_one_the_caller_supplied() -> None:
    # The engine reads no clock. A different stamp in means a different stamp out, and
    # nothing else changes.
    other = datetime(2031, 1, 1, tzinfo=UTC)
    assert evaluate(request(evaluated_at=other)).evaluated_at == other


# --- decision record invariants -----------------------------------------------------------


def unreadable_decision(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "policy_version": POLICY_VERSION,
        "effect": PolicyEffect.DENY,
        "reason": PolicyReason.EVALUATION_ERROR,
        "workflow_id": None,
        "action_id": None,
        "evaluated_at": None,
        "requester_id": None,
        "resource_id": None,
        "permission": None,
        "duration": None,
        "risk_tier": None,
    }
    fields.update(overrides)
    return fields


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_id", WORKFLOW),
        ("action_id", ACTION),
        ("evaluated_at", AT),
        ("requester_id", EmployeeId("E1042")),
        ("resource_id", ResourceId("wiki")),
        ("permission", Permission.READ),
        ("duration", AccessDuration.ONE_HOUR),
        ("risk_tier", RiskTier.LOW),
    ],
)
def test_echo_an_evaluation_error_decision_may_carry_nothing(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        PolicyDecision(**unreadable_decision(**{field: value}))


@pytest.mark.parametrize(
    "missing",
    [
        "workflow_id",
        "action_id",
        "evaluated_at",
        "requester_id",
        "permission",
        "duration",
        "risk_tier",
    ],
)
def test_echo_a_readable_decision_must_carry_every_required_field(missing: str) -> None:
    complete = unreadable_decision(
        effect=PolicyEffect.ALLOW,
        reason=PolicyReason.WITHIN_BASELINE,
        workflow_id=WORKFLOW,
        action_id=ACTION,
        evaluated_at=AT,
        requester_id=EmployeeId("E1042"),
        resource_id=ResourceId("wiki"),
        permission=Permission.READ,
        duration=AccessDuration.ONE_HOUR,
        risk_tier=RiskTier.LOW,
    )
    complete[missing] = None
    with pytest.raises(ValidationError):
        PolicyDecision(**complete)


def test_a_decision_rejects_mutation_and_unknown_fields() -> None:
    decision = evaluate(request())
    with pytest.raises(ValidationError):
        decision.effect = PolicyEffect.ALLOW
    with pytest.raises(ValidationError):
        PolicyDecision(**unreadable_decision(approved=True))


# --- rules the specification does support -------------------------------------------------


def test_an_unresolved_resource_is_denied() -> None:
    decision = evaluate(request(resource=None))
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason is PolicyReason.UNKNOWN_RESOURCE
    assert decision.resource_id is None
    assert decision.workflow_id == WORKFLOW


def test_an_inactive_requester_is_denied() -> None:
    decision = evaluate(request(requester=employee(is_active=False)))
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason is PolicyReason.REQUESTER_INACTIVE


def test_privileged_outranks_supplied_baseline() -> None:
    # The single place the engine overrides its input. A directory reporting admin baseline
    # on a privileged resource still cannot make the access automatic.
    decision = evaluate(
        request(
            resource=resource(ResourceClass.PRIVILEGED),
            permission=Permission.ADMIN,
            baseline_permission=Permission.ADMIN,
        )
    )
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.reason is PolicyReason.PRIVILEGED_RESOURCE


def test_permanent_privileged_access_is_reported_as_standing_access() -> None:
    decision = evaluate(
        request(
            resource=resource(ResourceClass.PRIVILEGED),
            duration=AccessDuration.PERMANENT,
        )
    )
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.reason is PolicyReason.STANDING_PRIVILEGED_ACCESS


def test_precedence_denies_an_inactive_requester_asking_for_privileged_access() -> None:
    decision = evaluate(
        request(
            requester=employee(is_active=False),
            resource=resource(ResourceClass.PRIVILEGED),
            permission=Permission.ADMIN,
            duration=AccessDuration.PERMANENT,
        )
    )
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason is PolicyReason.REQUESTER_INACTIVE


def test_precedence_reports_an_unresolved_resource_before_an_inactive_requester() -> None:
    decision = evaluate(request(resource=None, requester=employee(is_active=False)))
    assert decision.reason is PolicyReason.UNKNOWN_RESOURCE


# --- bypass attempts ----------------------------------------------------------------------


MALFORMED: list[Any] = [
    None,
    "E1042",
    {"requester": "E1042", "permission": "admin"},
    42,
    [WORKFLOW, ACTION],
]


@pytest.mark.parametrize("argument", MALFORMED)
def test_an_argument_that_is_not_a_request_fails_closed(argument: Any) -> None:
    decision = evaluate(argument)
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason is PolicyReason.EVALUATION_ERROR


def test_an_object_that_merely_looks_like_a_request_fails_closed() -> None:
    class LookAlike:
        workflow_id = WORKFLOW
        action_id = ACTION
        evaluated_at = AT
        requester = employee()
        resource = resource()
        permission = Permission.ADMIN
        duration = AccessDuration.PERMANENT
        baseline_permission = Permission.ADMIN
        risk_tier = RiskTier.LOW

    decision = evaluate(LookAlike())  # type: ignore[arg-type]
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason is PolicyReason.EVALUATION_ERROR


def test_an_unreadable_request_echoes_nothing() -> None:
    decision = evaluate("not a request")  # type: ignore[arg-type]
    for field in (
        decision.workflow_id,
        decision.action_id,
        decision.evaluated_at,
        decision.requester_id,
        decision.resource_id,
        decision.permission,
        decision.duration,
        decision.risk_tier,
    ):
        assert field is None


def test_a_self_built_resource_record_is_trusted_by_design() -> None:
    # The engine cannot tell a catalogue entry from a well-formed record the caller invented,
    # so downgrading a privileged resource to BASELINE wins an ALLOW. This is the contract,
    # not a defect: resolution is the caller's job. It is pinned here because it locates the
    # boundary — the runtime guard at S7 has to resolve the identifier through ResourceCatalog
    # itself and must never accept a Resource, or a baseline, from whatever proposed the
    # action.
    downgraded = Resource(
        resource_id=ResourceId("prod-db"),
        display_name="Production Database",
        resource_class=ResourceClass.BASELINE,
        owning_department=None,
    )
    assert evaluate(request(resource=downgraded)).effect is PolicyEffect.ALLOW

    catalogued = ResourceCatalog(load_resources()).get(ResourceId("prod-db"))
    assert evaluate(request(resource=catalogued)).effect is PolicyEffect.REQUIRE_APPROVAL


# --- purity and the exhaustive sweep ------------------------------------------------------


def test_evaluation_is_pure() -> None:
    first = evaluate(request())
    evaluate(request(resource=None, requester=employee(is_active=False)))
    evaluate(request(resource=resource(ResourceClass.PRIVILEGED), permission=Permission.ADMIN))
    assert evaluate(request()) == first


def test_exhaustive_sweep_never_allows_without_a_supplied_baseline() -> None:
    # Deny-by-default stated one-directionally so it cannot restate the implementation:
    # wherever ALLOW comes back, every condition that could justify it must independently
    # hold — and each one traces to a supplied input, not to a value the engine holds.
    allowed = 0
    evaluated = 0
    for resource_class, permission, duration, baseline, is_active in product(
        ResourceClass, Permission, AccessDuration, (None, *Permission), (True, False)
    ):
        built = request(
            requester=employee(is_active=is_active),
            resource=resource(resource_class),
            permission=permission,
            duration=duration,
            baseline_permission=baseline,
        )
        decision = evaluate(built)
        evaluated += 1
        if decision.effect is not PolicyEffect.ALLOW:
            continue
        allowed += 1
        assert baseline is not None
        assert PERMISSION_RANK[permission] <= PERMISSION_RANK[baseline]
        assert is_active
        assert resource_class is not ResourceClass.PRIVILEGED
        assert decision.reason is PolicyReason.WITHIN_BASELINE

    assert evaluated == 216
    assert allowed > 0


def test_an_unresolved_resource_never_allows() -> None:
    for permission, baseline in product(Permission, (None, *Permission)):
        decision = evaluate(
            request(resource=None, permission=permission, baseline_permission=baseline)
        )
        assert decision.effect is PolicyEffect.DENY


# --- the worked example from the specification --------------------------------------------


def test_the_specification_worked_example() -> None:
    # project.md 9.1: engineer + prod-db + admin + permanent -> human approval. No baseline is
    # supplied, because the privileged rule decides the case before baseline is consulted.
    directory = DirectoryBackend(load_employees(), load_baseline_access())
    catalog = ResourceCatalog(load_resources())
    engineer = directory.get_employee(EmployeeId("E1042"), EmployeeId("E1042"))

    decision = evaluate(
        request(
            requester=engineer,
            resource=catalog.get(ResourceId("prod-db")),
            permission=Permission.ADMIN,
            duration=AccessDuration.PERMANENT,
            baseline_permission=None,
            risk_tier=RiskTier.CRITICAL,
        )
    )

    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.reason is PolicyReason.STANDING_PRIVILEGED_ACCESS
    assert decision.resource_id == ResourceId("prod-db")
    assert decision.workflow_id == WORKFLOW
    assert decision.action_id == ACTION


def test_a_seeded_deactivated_account_is_denied() -> None:
    directory = DirectoryBackend(load_employees(), load_baseline_access())
    catalog = ResourceCatalog(load_resources())
    former = directory.get_employee(EmployeeId("E9099"), EmployeeId("E9099"))

    decision = evaluate(request(requester=former, resource=catalog.get(ResourceId("wiki"))))

    assert decision.effect is PolicyEffect.DENY
    assert decision.reason is PolicyReason.REQUESTER_INACTIVE


# --- the golden decision matrix -----------------------------------------------------------


# Every reachable combination against the effect and reason it produces, written out rather than
# derived, so that editing a rule in _classify fails here. POLICY_VERSION is asserted alongside:
# an approval record binds the version that was in force, so a rule change without a version bump
# would let a decision reached under the old rules authorise execution under the new ones. The
# only way to make this test pass again after a deliberate rule change is to update the row and
# bump the version.
GOLDEN_DECISIONS: dict[
    tuple[ResourceClass, bool, AccessDuration, Permission, Permission | None],
    tuple[PolicyEffect, PolicyReason],
] = {}

for _resource_class in ResourceClass:
    for _is_active in (True, False):
        for _duration in AccessDuration:
            for _permission in Permission:
                for _baseline in (None, *Permission):
                    if not _is_active:
                        _expected = (PolicyEffect.DENY, PolicyReason.REQUESTER_INACTIVE)
                    elif _resource_class is ResourceClass.PRIVILEGED:
                        _expected = (
                            (
                                PolicyEffect.REQUIRE_APPROVAL,
                                PolicyReason.STANDING_PRIVILEGED_ACCESS,
                            )
                            if _duration is AccessDuration.PERMANENT
                            else (
                                PolicyEffect.REQUIRE_APPROVAL,
                                PolicyReason.PRIVILEGED_RESOURCE,
                            )
                        )
                    elif (
                        _baseline is None
                        or PERMISSION_RANK[_permission] > PERMISSION_RANK[_baseline]
                    ):
                        _expected = (
                            PolicyEffect.REQUIRE_APPROVAL,
                            PolicyReason.EXCEEDS_BASELINE_PERMISSION,
                        )
                    else:
                        _expected = (PolicyEffect.ALLOW, PolicyReason.WITHIN_BASELINE)
                    GOLDEN_DECISIONS[
                        _resource_class, _is_active, _duration, _permission, _baseline
                    ] = _expected


@pytest.mark.parametrize(("key", "expected"), sorted(GOLDEN_DECISIONS.items(), key=str))
def test_the_decision_matrix_is_pinned(
    key: tuple[ResourceClass, bool, AccessDuration, Permission, Permission | None],
    expected: tuple[PolicyEffect, PolicyReason],
) -> None:
    resource_class, is_active, duration, permission, baseline = key
    decision = evaluate(
        request(
            requester=employee(is_active=is_active),
            resource=resource(resource_class=resource_class),
            permission=permission,
            duration=duration,
            baseline_permission=baseline,
        )
    )
    assert (decision.effect, decision.reason) == expected


def test_the_matrix_covers_every_reachable_combination() -> None:
    expected = (
        len(ResourceClass) * 2 * len(AccessDuration) * len(Permission) * (len(Permission) + 1)
    )
    assert len(GOLDEN_DECISIONS) == expected


def test_the_pinned_matrix_belongs_to_a_stated_policy_version() -> None:
    # An approval binds this value. Changing a rule above without changing this one would let a
    # decision reached under the old rules authorise execution under the new ones.
    assert POLICY_VERSION == "1"
