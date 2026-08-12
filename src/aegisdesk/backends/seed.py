import json
from collections.abc import Mapping, Sequence
from importlib import resources
from importlib.abc import Traversable
from typing import Any

from aegisdesk.backends.kb import KbDocument
from aegisdesk.domain.employee import Employee
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
