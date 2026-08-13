import json
from pathlib import Path

import pytest

from aegisdesk.backends import seed
from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.seed import (
    load_approval_policy,
    load_employees,
    load_resources,
    load_reviewers,
)
from aegisdesk.domain.enums import Department, ResourceClass
from aegisdesk.domain.errors import DomainInvariantError, UnknownResourceError
from aegisdesk.domain.ids import EmployeeId, ResourceId, ReviewerId


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


# --- the reviewer roster ------------------------------------------------------------------


def test_the_roster_names_only_known_active_employees() -> None:
    employees = load_employees()
    roster = load_reviewers()
    assert roster
    for reviewer in roster:
        assert employees[EmployeeId(reviewer)].is_active


def test_no_reviewer_is_also_a_fixture_requester() -> None:
    # The self-approval rule would otherwise pass for the wrong reason in the guard fixtures.
    roster = load_reviewers()
    assert roster.isdisjoint({ReviewerId("E1042"), ReviewerId("E1043"), ReviewerId("E9099")})


def test_the_roster_is_stated_rather_than_derived_from_a_role() -> None:
    # Deriving reviewers from EmployeeRole would put a company policy value into code, which is
    # the position taken for baseline access and risk tiers.
    employees = load_employees()
    roles = {employees[EmployeeId(reviewer)].role for reviewer in load_reviewers()}
    assert len(roles) > 1


def test_a_roster_entry_naming_nobody_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_employees(tmp_path)
    (tmp_path / "reviewers.json").write_text(
        json.dumps([{"reviewer_id": "E9999"}]), encoding="utf-8"
    )
    monkeypatch.setattr(seed, "_seeds_root", lambda: tmp_path)
    with pytest.raises(DomainInvariantError, match="unknown employees"):
        seed.load_reviewers()


def test_a_duplicate_roster_entry_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_employees(tmp_path)
    (tmp_path / "reviewers.json").write_text(
        json.dumps([{"reviewer_id": "E1042"}, {"reviewer_id": "E1042"}]), encoding="utf-8"
    )
    monkeypatch.setattr(seed, "_seeds_root", lambda: tmp_path)
    with pytest.raises(DomainInvariantError, match="duplicate reviewer_id"):
        seed.load_reviewers()


def test_an_inactive_roster_entry_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_employees(tmp_path, is_active=False)
    (tmp_path / "reviewers.json").write_text(
        json.dumps([{"reviewer_id": "E1042"}]), encoding="utf-8"
    )
    monkeypatch.setattr(seed, "_seeds_root", lambda: tmp_path)
    with pytest.raises(DomainInvariantError, match="inactive employees"):
        seed.load_reviewers()


def _seed_employees(tmp_path: Path, is_active: bool = True) -> None:
    (tmp_path / "employees.json").write_text(
        json.dumps(
            [
                {
                    "employee_id": "E1042",
                    "display_name": "Priya Raghunathan",
                    "department": "engineering",
                    "role": "individual_contributor",
                    "manager_id": None,
                    "is_active": is_active,
                }
            ]
        ),
        encoding="utf-8",
    )


# --- the approval time-box corpus ---------------------------------------------------------


def test_the_approval_time_boxes_are_the_configured_values() -> None:
    policy = load_approval_policy()
    assert policy.pending_ttl_hours == 72
    assert policy.approved_ttl_hours == 4


def test_an_approval_policy_that_is_not_an_object_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "approval_policy.json").write_text(json.dumps([]), encoding="utf-8")
    monkeypatch.setattr(seed, "_seeds_root", lambda: tmp_path)
    with pytest.raises(DomainInvariantError, match="must contain a JSON object"):
        seed.load_approval_policy()
