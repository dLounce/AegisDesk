import json
from pathlib import Path

import pytest

from aegisdesk.backends import seed
from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.seed import load_employees, load_resources
from aegisdesk.domain.enums import Department, ResourceClass
from aegisdesk.domain.errors import DomainInvariantError, UnknownResourceError
from aegisdesk.domain.ids import ResourceId


def test_every_department_is_represented() -> None:
    departments = {employee.department for employee in load_employees().values()}
    assert departments == set(Department)


def test_seed_includes_an_inactive_employee() -> None:
    # Needed so later steps can test that policy fails closed for a deactivated requester.
    assert any(not employee.is_active for employee in load_employees().values())


def test_manager_references_resolve() -> None:
    employees = load_employees()
    for employee in employees.values():
        if employee.manager_id is not None:
            assert employee.manager_id in employees


def test_catalogue_covers_every_resource_class() -> None:
    classes = {resource.resource_class for resource in load_resources().values()}
    assert classes == set(ResourceClass)


def test_privileged_resources_are_the_expected_ones() -> None:
    privileged = {
        resource_id
        for resource_id, resource in load_resources().items()
        if resource.resource_class is ResourceClass.PRIVILEGED
    }
    assert privileged == {ResourceId("prod-db"), ResourceId("prod-k8s"), ResourceId("payroll")}


def test_baseline_resources_are_company_wide() -> None:
    for resource in load_resources().values():
        if resource.resource_class is ResourceClass.BASELINE:
            assert resource.owning_department is None


def test_non_baseline_resources_have_an_owning_department() -> None:
    for resource in load_resources().values():
        if resource.resource_class is not ResourceClass.BASELINE:
            assert resource.owning_department is not None


def test_unknown_resource_fails_closed() -> None:
    catalog = ResourceCatalog(load_resources())
    with pytest.raises(UnknownResourceError):
        catalog.get(ResourceId("prod-db-staging"))


def test_catalogue_lookup_returns_the_classified_entry() -> None:
    catalog = ResourceCatalog(load_resources())
    resource = catalog.get(ResourceId("prod-db"))
    assert resource.resource_class is ResourceClass.PRIVILEGED
    assert resource.owning_department is Department.ENGINEERING


def test_malformed_seed_payload_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Decoded JSON is Any, so the array-of-objects shape has to be checked rather than
    # assumed. Pointing the loader at a malformed file exercises that check directly.
    (tmp_path / "employees.json").write_text('{"E1042": "not a list"}', encoding="utf-8")
    monkeypatch.setattr(seed, "_seeds_root", lambda: tmp_path)
    with pytest.raises(DomainInvariantError, match="JSON array of objects"):
        seed.load_employees()


def test_duplicate_employee_ids_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = {
        "employee_id": "E1042",
        "display_name": "Duplicate",
        "department": "engineering",
        "role": "individual_contributor",
        "manager_id": None,
        "is_active": True,
    }
    (tmp_path / "employees.json").write_text(json.dumps([row, row]), encoding="utf-8")
    monkeypatch.setattr(seed, "_seeds_root", lambda: tmp_path)
    with pytest.raises(DomainInvariantError, match="duplicate employee_id"):
        seed.load_employees()


def test_dangling_manager_reference_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = {
        "employee_id": "E1042",
        "display_name": "Orphan",
        "department": "engineering",
        "role": "individual_contributor",
        "manager_id": "E9999",
        "is_active": True,
    }
    (tmp_path / "employees.json").write_text(json.dumps([row]), encoding="utf-8")
    monkeypatch.setattr(seed, "_seeds_root", lambda: tmp_path)
    with pytest.raises(DomainInvariantError, match="unknown managers"):
        seed.load_employees()
