from aegisdesk.domain.enums import ApprovalRefusalReason


class AegisDeskError(Exception):
    pass


# Subclasses ValueError so that a violation raised inside a Pydantic validator is collected
# into that model's ValidationError alongside ordinary field errors, while still being
# distinguishable as a domain invariant breach rather than a type or format problem.
class DomainInvariantError(AegisDeskError, ValueError):
    pass


class UnknownEmployeeError(AegisDeskError):
    pass


class UnknownResourceError(AegisDeskError):
    pass


# Raised whenever a requester asks for another employee's record, whether or not that
# employee exists. Reporting "unknown employee" for a non-existent target would turn the
# directory into a membership oracle.
class CrossEmployeeAccessError(AegisDeskError):
    pass


# Raised both for a ticket that does not exist and for one belonging to another employee.
# A ticket the requester does not own does not exist as far as that requester is concerned;
# separate errors would let a caller enumerate real ticket ids by comparing failures.
class TicketNotFoundError(AegisDeskError):
    pass


class IllegalTicketTransitionError(AegisDeskError):
    pass


# Raised for an absent, malformed, or unresolved identity claim alike, with one message for
# all three. Distinguishing them would let a caller probe the session boundary to learn which
# employee identifiers are real, which is the oracle CrossEmployeeAccessError already avoids.
class SessionAuthenticationError(AegisDeskError):
    pass


# Raised when the access backend is called with anything other than a receipt the guard
# produced. The backend has no other entry point, so this is what a caller that skipped the
# authorization path meets.
class ProtectedExecutionError(AegisDeskError):
    pass


# Raised for every refused reviewer decision, with one message for all of them. The precise
# cause travels on `reason`, which is bound for the audit trail rather than for a caller
# comparing replies.
class ApprovalDecisionError(AegisDeskError):
    def __init__(self, reason: ApprovalRefusalReason) -> None:
        super().__init__("the approval decision was refused")
        self.reason = reason


# Raised when a workflow already holds as many pending approvals as it is allowed. Separate
# from the decision error because it is refused on the proposing side, before any reviewer
# is involved.
class ApprovalCapacityError(AegisDeskError):
    pass
