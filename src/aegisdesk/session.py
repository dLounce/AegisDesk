from datetime import datetime
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict

from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.domain.errors import AegisDeskError, SessionAuthenticationError
from aegisdesk.domain.ids import EmployeeId, ReviewerId

# project.md 11 describes the mock session layer as presenting an identifier the backend
# treats as authenticated because it arrives from the session layer rather than from
# conversation text. This module is that layer: it turns one claimed identifier into a typed
# session record, and it is the only place in the system where an identity string becomes an
# identity. A real deployment would verify a credential here; the mock verifies a bound,
# well-formed string against the directory, which is a stated limitation rather than
# authentication.

# The claim arrives from a transport header, so it is bounded where it enters rather than
# trusted to be reasonable.
MAX_CLAIMED_ID_LENGTH: Final = 64

_AUTHENTICATION_FAILED: Final = "session authentication failed"


# Identity alone. A cached Employee record would go stale across a pause, and DESIGN.md 4
# requires a resuming workflow to re-read authoritative requester state, so callers hold the
# identifier and read the record when they need it. No permission, resource, or risk value
# belongs here: those are per action, and a session that carried them would freeze for the
# run what has to be re-evaluated on resume.
class EmployeeSessionContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    employee_id: EmployeeId
    authenticated_at: AwareDatetime


# A separate type rather than a flag on the record above, so a reviewer session cannot stand
# in for a requester session by accident: the substitution is a type error, not a value to
# check for. What a reviewer is permitted to decide is not defined by any governing document
# and is deliberately absent here.
class ReviewerSessionContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    reviewer_id: ReviewerId
    authenticated_at: AwareDatetime


def authenticate_employee(
    claimed_id: str, directory: DirectoryBackend, now: datetime
) -> EmployeeSessionContext:
    return EmployeeSessionContext(
        employee_id=_resolve(claimed_id, directory),
        authenticated_at=now,
    )


# Reviewers resolve through the same directory, so reviewer and employee identifiers name the
# same people. That is what makes the rule against approving one's own action checkable at
# all: an approval can only be compared to its requester if the two identifiers are drawn
# from one namespace.
def authenticate_reviewer(
    claimed_id: str, directory: DirectoryBackend, now: datetime
) -> ReviewerSessionContext:
    return ReviewerSessionContext(
        reviewer_id=ReviewerId(_resolve(claimed_id, directory)),
        authenticated_at=now,
    )


def _resolve(claimed_id: str, directory: DirectoryBackend) -> EmployeeId:
    # The annotation is a promise, not a check. This value reaches the process from a
    # transport header and, later, from a deserialised checkpoint, so its type is verified
    # here for the same reason policy.evaluate re-checks the argument it was handed.
    if not isinstance(claimed_id, str):
        raise SessionAuthenticationError(_AUTHENTICATION_FAILED)
    if not 1 <= len(claimed_id) <= MAX_CLAIMED_ID_LENGTH:
        raise SessionAuthenticationError(_AUTHENTICATION_FAILED)
    # Surrounding whitespace and control characters are refused rather than stripped: a claim
    # that needed cleaning up is a claim the session layer did not produce, and normalising it
    # would let two different strings authenticate as one identity.
    if claimed_id != claimed_id.strip() or not claimed_id.isprintable():
        raise SessionAuthenticationError(_AUTHENTICATION_FAILED)

    employee_id = EmployeeId(claimed_id)
    try:
        directory.get_employee(employee_id, employee_id)
    except AegisDeskError:
        # Chaining would put the distinction this boundary exists to remove back into the
        # traceback.
        raise SessionAuthenticationError(_AUTHENTICATION_FAILED) from None
    # Whether the record is active is deliberately not consulted. Authentication establishes
    # who is asking; policy decides what they may do, and it already refuses an inactive
    # requester with a stated reason.
    return employee_id
