import json
from collections.abc import Mapping, Sequence
from importlib import resources
from importlib.abc import Traversable
from itertools import product
from typing import Any

from pydantic import BaseModel, ConfigDict

from aegisdesk.backends.kb import KbDocument
from aegisdesk.domain.employee import Employee
from aegisdesk.domain.enums import (
    AccessDuration,
    Permission,
    ResourceClass,
    RiskTier,
    RiskTierConfiguration,
)
from aegisdesk.domain.errors import DomainInvariantError
from aegisdesk.domain.ids import EmployeeId, ResourceId
from aegisdesk.domain.resource import Resource

# Identifies the deliberately poisoned knowledge-base article. It carries injected
# instructions and exists so that every later layer has a permanent fixture to be tested
# against. Nothing filters on this value at retrieval time: the document is returned by
# ordinary search exactly like any other, because a fixture the system recognises and
# quietly excludes would prove nothing.
POISONED_FIXTURE_DOCUMENT_ID = "POISONED-FIXTURE-database-access"


def _seeds_root() -> Traversable:
    return resources.files("aegisdesk") / "seeds"


def _read_json(name: str) -> list[dict[str, Any]]:
    payload: Any = json.loads((_seeds_root() / name).read_text(encoding="utf-8"))
    # Decoded JSON is Any. Annotating it as a list of objects without checking would hand
    # mypy a guarantee nothing verified, and a malformed seed file would surface later as a
    # confusing validation error instead of a clear one here.
    if not isinstance(payload, list) or not all(isinstance(row, dict) for row in payload):
        raise DomainInvariantError(f"{name} must contain a JSON array of objects")
    rows: list[dict[str, Any]] = payload
    return rows


def load_employees() -> Mapping[EmployeeId, Employee]:
    rows = _read_json("employees.json")
    employees = {
        employee.employee_id: employee
        for employee in (Employee.model_validate(row) for row in rows)
    }
    if len(employees) != len(rows):
        raise DomainInvariantError("duplicate employee_id in seed data")

    # A manager reference pointing at nobody would leave the org graph broken in a way that
    # only surfaces later, inside policy evaluation.
    dangling = {
        employee.manager_id
        for employee in employees.values()
        if employee.manager_id is not None and employee.manager_id not in employees
    }
    if dangling:
        raise DomainInvariantError(f"seed employees reference unknown managers: {sorted(dangling)}")
    return employees


def load_resources() -> Mapping[ResourceId, Resource]:
    rows = _read_json("resources.json")
    catalogue = {
        resource.resource_id: resource
        for resource in (Resource.model_validate(row) for row in rows)
    }
    if len(catalogue) != len(rows):
        raise DomainInvariantError("duplicate resource_id in seed data")
    return catalogue


# One explicit grant per employee and resource. The corpus states what each person holds
# rather than a rule that derives it, so no layer of the system needs a role or department
# table to answer what the baseline is, and no company policy value is defined in code.
class _BaselineAccessRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    employee_id: EmployeeId
    resource_id: ResourceId
    permission: Permission


def load_baseline_access() -> Mapping[tuple[EmployeeId, ResourceId], Permission]:
    rows = _read_json("baseline_access.json")
    parsed = [_BaselineAccessRow.model_validate(row) for row in rows]
    baseline = {(row.employee_id, row.resource_id): row.permission for row in parsed}
    if len(baseline) != len(parsed):
        raise DomainInvariantError("duplicate employee_id and resource_id pair in seed data")

    # A grant naming an employee or a resource that does not exist is a baseline nobody can
    # reach, and the gap would surface later as an escalation with no visible cause.
    employees = load_employees()
    catalogue = load_resources()
    dangling = {pair for pair in baseline if pair[0] not in employees or pair[1] not in catalogue}
    if dangling:
        raise DomainInvariantError(
            f"seed baseline access references unknown pairs: {sorted(dangling)}"
        )
    return baseline


# Risk tiers are reference configuration for the fictional company, not a rule derived from
# the specification. project.md 9 requires the policy to define tiers and 9.1 requires the tier
# on the decision, but no section states a mapping, so the corpus states one triple at a time
# and no layer of the system computes a tier. The engine still records the tier without
# consulting it; what this corpus fixes is that the value reaching it is configuration rather
# than something a model chose.
class _RiskTierRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_class: ResourceClass
    permission: Permission
    duration: AccessDuration
    risk_tier: RiskTier


def load_risk_tiers() -> RiskTierConfiguration:
    rows = _read_json("risk_tiers.json")
    parsed = [_RiskTierRow.model_validate(row) for row in rows]
    tiers = {(row.resource_class, row.permission, row.duration): row.risk_tier for row in parsed}
    if len(tiers) != len(parsed):
        raise DomainInvariantError("duplicate risk tier key in seed data")

    # An absent triple would leave the guard with no tier for a request it can otherwise
    # resolve. The guard refuses in that case, so an incomplete corpus turns into a refusal of
    # real work rather than a wrong tier; catching it here makes the gap visible at start-up.
    every_triple = product(ResourceClass, Permission, AccessDuration)
    missing = [
        f"{resource_class.value}/{permission.value}/{duration.value}"
        for resource_class, permission, duration in every_triple
        if (resource_class, permission, duration) not in tiers
    ]
    if missing:
        raise DomainInvariantError(f"risk tier corpus does not cover: {sorted(missing)}")
    return tiers


def load_kb_documents() -> Sequence[KbDocument]:
    documents = []
    for entry in sorted(_seeds_root().joinpath("kb").iterdir(), key=lambda item: item.name):
        if not entry.name.endswith(".md"):
            continue
        title, _, body = entry.read_text(encoding="utf-8").partition("\n")
        documents.append(
            KbDocument(
                document_id=entry.name.removesuffix(".md"),
                title=title.lstrip("# ").strip(),
                body=body.strip(),
            )
        )
    if not documents:
        raise DomainInvariantError("knowledge base seed directory is empty")
    return tuple(documents)
