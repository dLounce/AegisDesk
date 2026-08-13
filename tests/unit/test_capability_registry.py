from typing import Any

import pytest

from aegisdesk.capabilities import (
    AGENT_CAPABILITIES,
    PRIVILEGED_CAPABILITIES,
    REQUIRED_CAPABILITY,
    assert_least_privilege,
    holds,
)
from aegisdesk.domain.enums import AgentName, Capability, ProtectedOperation
from aegisdesk.domain.errors import DomainInvariantError


def test_the_resolver_holds_no_privileged_capability() -> None:
    assert AGENT_CAPABILITIES[AgentName.RESOLVER].isdisjoint(PRIVILEGED_CAPABILITIES)


def test_the_resolver_cannot_propose_a_grant() -> None:
    assert not holds(AgentName.RESOLVER, Capability.ACCESS_PROPOSE_GRANT)


def test_the_escalation_agent_may_propose_a_grant() -> None:
    assert holds(AgentName.ESCALATION, Capability.ACCESS_PROPOSE_GRANT)


def test_the_router_holds_nothing() -> None:
    assert AGENT_CAPABILITIES[AgentName.ROUTER] == frozenset()


def test_the_invariant_is_checked_rather_than_asserted_in_a_test() -> None:
    # The same call runs at import time, so a build in which the Resolver holds a privileged
    # capability does not start. This exercises the check itself against a violating registry.
    violating = {AgentName.RESOLVER: frozenset({Capability.ACCESS_PROPOSE_GRANT})}
    with pytest.raises(DomainInvariantError):
        assert_least_privilege(violating, PRIVILEGED_CAPABILITIES)


def test_the_invariant_covers_a_capability_added_to_the_privileged_set_later() -> None:
    # Stated negatively, so a capability that becomes privileged is refused for the Resolver
    # without anybody remembering to revisit the registry.
    widened = PRIVILEGED_CAPABILITIES | {Capability.TICKET_SET_STATUS}
    assert_least_privilege(AGENT_CAPABILITIES, frozenset(widened))
    violating = {AgentName.RESOLVER: frozenset({Capability.TICKET_SET_STATUS})}
    with pytest.raises(DomainInvariantError):
        assert_least_privilege(violating, frozenset(widened))


def test_values_are_frozen_sets_so_a_caller_cannot_widen_a_grant() -> None:
    for granted in AGENT_CAPABILITIES.values():
        assert isinstance(granted, frozenset)


@pytest.mark.parametrize("agent", ["escalation", None, 1, AgentName])
def test_an_agent_outside_the_registry_holds_nothing(agent: Any) -> None:
    assert not holds(agent, Capability.ACCESS_PROPOSE_GRANT)


def test_an_unlisted_capability_is_refused() -> None:
    assert not holds(AgentName.ESCALATION, Capability.TICKET_SET_STATUS)


def test_proposing_a_protected_operation_requires_a_privileged_capability() -> None:
    # A protected operation whose proposal required an ordinary capability would put execution
    # of privileged work behind a grant every agent could hold.
    for required in REQUIRED_CAPABILITY.values():
        assert required in PRIVILEGED_CAPABILITIES


def test_the_capability_registry_names_no_protected_operation() -> None:
    # The two enums stay separate: holding a capability permits proposing, and no value an
    # agent holds is the argument that authorises execution.
    granted: set[Capability] = set()
    for capabilities in AGENT_CAPABILITIES.values():
        granted |= capabilities
    assert granted.isdisjoint(set(ProtectedOperation))
