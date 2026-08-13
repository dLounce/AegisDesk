from collections.abc import Mapping
from enum import Enum
from typing import Final

# Every enum here is a plain Enum rather than a str-backed one. A str-backed member
# compares equal to a bare string, which would let raw strings from model output or
# checkpoint deserialisation satisfy a security check that expects an enum. Conversion from
# a string must go through an explicit lookup that raises on unknown input.


class AgentName(Enum):
    ROUTER = "router"
    RESOLVER = "resolver"
    ESCALATION = "escalation"


class Department(Enum):
    ENGINEERING = "engineering"
    PRODUCT = "product"
    SALES = "sales"
    FINANCE = "finance"
    HR = "hr"
    OPERATIONS = "operations"


# Job function, kept orthogonal to Department. A combined enum (finance_manager,
# engineering_manager, ...) would multiply out to one member per department per level,
# which is the standard route to role explosion. Scope comes from Department, authority
# level from EmployeeRole, and policy reads both.
class EmployeeRole(Enum):
    INDIVIDUAL_CONTRIBUTOR = "individual_contributor"
    MANAGER = "manager"
    IT_ADMIN = "it_admin"
    EXECUTIVE = "executive"


class Permission(Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


# Privilege ordering is declared as data. Neither member declaration order nor string
# comparison is a safe source of ordering: alphabetically "admin" < "read" < "write", so a
# str-backed comparison would rank admin as the least privileged value and quietly approve
# every admin request.
PERMISSION_RANK: Final[Mapping[Permission, int]] = {
    Permission.READ: 0,
    Permission.WRITE: 1,
    Permission.ADMIN: 2,
}


class RiskTier(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_RANK: Final[Mapping[RiskTier, int]] = {
    RiskTier.LOW: 0,
    RiskTier.MEDIUM: 1,
    RiskTier.HIGH: 2,
    RiskTier.CRITICAL: 3,
}


class AccessDuration(Enum):
    ONE_HOUR = "one_hour"
    EIGHT_HOURS = "eight_hours"
    PERMANENT = "permanent"


# None means the grant does not expire. PERMANENT is an explicit member rather than an
# absent or null duration so that standing access is a value a reviewer sees stated, never
# something inferred from a field a malformed tool call happened to omit.
DURATION_MAX_HOURS: Final[Mapping[AccessDuration, int | None]] = {
    AccessDuration.ONE_HOUR: 1,
    AccessDuration.EIGHT_HOURS: 8,
    AccessDuration.PERMANENT: None,
}


class ResourceClass(Enum):
    BASELINE = "baseline"
    SENSITIVE = "sensitive"
    PRIVILEGED = "privileged"


# What an agent may attempt. Every member names a verb, and no member denotes execution of
# a protected operation: an agent can propose a grant, never perform one.
class Capability(Enum):
    KB_SEARCH = "kb.search"
    TICKET_READ = "ticket.read"
    TICKET_APPEND_NOTE = "ticket.append_note"
    TICKET_SET_STATUS = "ticket.set_status"
    DIRECTORY_READ_SELF = "directory.read_self"
    ACCESS_PROPOSE_GRANT = "access.propose_grant"


# What the runtime executes once an authoritative approval exists. Deliberately a separate
# type from Capability so that no agent capability can ever be the argument that authorises
# execution.
class ProtectedOperation(Enum):
    GRANT_ACCESS = "grant_access"


class TicketStatus(Enum):
    OPEN = "open"
    AWAITING_INFO = "awaiting_info"
    PENDING_APPROVAL = "pending_approval"
    RESOLVED = "resolved"
    REJECTED = "rejected"


class PolicyEffect(Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyReason(Enum):
    WITHIN_BASELINE = "within_baseline"
    EXCEEDS_BASELINE_PERMISSION = "exceeds_baseline_permission"
    PRIVILEGED_RESOURCE = "privileged_resource"
    STANDING_PRIVILEGED_ACCESS = "standing_privileged_access"
    DEPARTMENT_MISMATCH = "department_mismatch"
    UNKNOWN_RESOURCE = "unknown_resource"
    REQUESTER_INACTIVE = "requester_inactive"
    EVALUATION_ERROR = "evaluation_error"


# APPROVED is deliberately not the first member, so that any code reaching for a positional
# default lands on PENDING rather than on the one value that authorises execution.
class ApprovalStatus(Enum):
    PENDING = "pending"
    REJECTED = "rejected"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    APPROVED = "approved"


class ActorType(Enum):
    EMPLOYEE = "employee"
    REVIEWER = "reviewer"
    AGENT = "agent"
    RUNTIME = "runtime"
    BACKEND = "backend"


# What the runtime guard did. AWAITING_APPROVAL is a third outcome rather than a flavour of
# refusal, because a paused action is not a denied one and the two are audited differently.
# REFUSED is still first, so code reaching for a positional default lands on the refusal, and
# EXECUTED is last, so neither of the other two can be reached by an off-by-one.
class GuardOutcome(Enum):
    REFUSED = "refused"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTED = "executed"


# Why the guard refused. This travels on the outcome record for the audit trail and never
# reaches the model, which sees one message whatever the reason.
class GuardRefusalReason(Enum):
    UNTRUSTED_SESSION = "untrusted_session"
    MALFORMED_PROPOSAL = "malformed_proposal"
    MISSING_CAPABILITY = "missing_capability"
    UNRESOLVED_REQUESTER = "unresolved_requester"
    UNRESOLVED_TICKET = "unresolved_ticket"
    UNRESOLVED_RESOURCE = "unresolved_resource"
    UNCLASSIFIED_RISK = "unclassified_risk"
    POLICY_REFUSED = "policy_refused"
    APPROVAL_LIMIT_REACHED = "approval_limit_reached"
    # A proposal that found a record already decided against, or one that has lapsed. Separated
    # so that an agent re-proposing an action a human turned down is a distinct audit line from
    # a request that simply timed out.
    APPROVAL_ALREADY_REJECTED = "approval_already_rejected"
    APPROVAL_LAPSED = "approval_lapsed"
    # The five checks the resume path runs against the authoritative approval record.
    NO_APPROVAL_RECORD = "no_approval_record"
    APPROVAL_NOT_GRANTED = "approval_not_granted"
    ARGUMENT_DIGEST_MISMATCH = "argument_digest_mismatch"
    DECISION_TUPLE_MISMATCH = "decision_tuple_mismatch"
    REVIEWER_NOT_ELIGIBLE = "reviewer_not_eligible"
    EXPIRED_GRANT_REPLAY = "expired_grant_replay"


# Why the approval store refused a reviewer decision. Kept off the exception message for the
# same reason the guard keeps its refusal reason off the model's reply: a caller comparing
# messages could otherwise learn which approvals exist and which reviewers are on the roster.
class ApprovalRefusalReason(Enum):
    UNTRUSTED_REVIEWER_SESSION = "untrusted_reviewer_session"
    MALFORMED_DECISION = "malformed_decision"
    REVIEWER_NOT_ON_ROSTER = "reviewer_not_on_roster"
    REVIEWER_INACTIVE = "reviewer_inactive"
    UNKNOWN_APPROVAL = "unknown_approval"
    SELF_APPROVAL = "self_approval"
    ILLEGAL_TRANSITION = "illegal_transition"


# The risk tier in force for a resolved request, supplied as configuration. project.md 9
# requires the policy to define tiers and 9.1 requires the tier on a decision, but no section
# states a mapping, so the shape is declared here and the values live in seed configuration.
RiskTierConfiguration = Mapping[tuple[ResourceClass, Permission, AccessDuration], RiskTier]
