from collections.abc import Mapping
from typing import Final

from aegisdesk.domain.enums import AgentName, Capability, ProtectedOperation
from aegisdesk.domain.errors import DomainInvariantError

# Capabilities that reach access_api. project.md 8.2 puts access_api out of the Resolver's
# reach and 8.3 gives proposing privileged work to Escalation; both are stated, so both are
# encoded. Membership here is what the Resolver invariant below is checked against, which
# means a capability added to this set later is refused for the Resolver by construction.
PRIVILEGED_CAPABILITIES: Final[frozenset[Capability]] = frozenset(
    {
        Capability.ACCESS_PROPOSE_GRANT,
        Capability.ACCESS_PROPOSE_REVOKE,
        Capability.ACCESS_PROPOSE_MODIFY,
    }
)

# Only the grants the governing documents state. Nothing is inferred from an agent's prose
# responsibilities: an unlisted capability is refused and an unlisted agent is refused, so a
# tool binding that has not been decided yet reaches nobody. The sets for Router and Resolver
# are empty rather than absent because an empty set is a decision on the record, and because
# the Resolver invariant needs something to assert against.
AGENT_CAPABILITIES: Final[Mapping[AgentName, frozenset[Capability]]] = {
    AgentName.ROUTER: frozenset(),
    AgentName.RESOLVER: frozenset(),
    AgentName.ESCALATION: frozenset(
        {
            Capability.ACCESS_PROPOSE_GRANT,
            Capability.ACCESS_PROPOSE_REVOKE,
            Capability.ACCESS_PROPOSE_MODIFY,
        }
    ),
}

# Which capability a proposal of each protected operation requires. The two enums stay
# separate: holding the capability permits proposing the operation and nothing else, so no
# value an agent holds is ever the argument that authorises execution. A ProtectedOperation
# absent from this mapping has no capability that can propose it, which is the deny-by-default
# position for an operation added to the enum before its binding is decided.
REQUIRED_CAPABILITY: Final[Mapping[ProtectedOperation, Capability]] = {
    ProtectedOperation.GRANT_ACCESS: Capability.ACCESS_PROPOSE_GRANT,
    ProtectedOperation.REVOKE_ACCESS: Capability.ACCESS_PROPOSE_REVOKE,
    ProtectedOperation.MODIFY_PERMISSIONS: Capability.ACCESS_PROPOSE_MODIFY,
}


def holds(agent: AgentName, capability: Capability) -> bool:
    return capability in AGENT_CAPABILITIES.get(agent, frozenset())


def assert_least_privilege(
    registry: Mapping[AgentName, frozenset[Capability]],
    privileged: frozenset[Capability],
) -> None:
    if not registry.get(AgentName.RESOLVER, frozenset()).isdisjoint(privileged):
        raise DomainInvariantError("the Resolver must hold no privileged capability")


# Checked on import rather than left to a test somebody could skip. A build in which the
# Resolver holds a privileged capability does not start.
assert_least_privilege(AGENT_CAPABILITIES, PRIVILEGED_CAPABILITIES)
