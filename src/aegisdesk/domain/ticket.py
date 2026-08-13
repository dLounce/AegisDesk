from collections.abc import Mapping
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from aegisdesk.domain.enums import ActorType, TicketStatus
from aegisdesk.domain.ids import EmployeeId, TicketId

SUBJECT_MAX_LENGTH = 200
BODY_MAX_LENGTH = 4000
AUTHOR_ID_MAX_LENGTH = 64


class Ticket(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ticket_id: TicketId
    # Comes from the authenticated session, never from ticket text.
    requester_id: EmployeeId
    # Employee-supplied and therefore untrusted: it may contain instructions aimed at an
    # agent and must never be treated as policy, identity, or authorization. Bounded because
    # this value reaches prompts, audit records, and the reviewer's screen, all of which are
    # places an unbounded string is a problem.
    subject: str = Field(min_length=1, max_length=SUBJECT_MAX_LENGTH)
    status: TicketStatus
    created_at: AwareDatetime
    updated_at: AwareDatetime


class TicketMessage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ticket_id: TicketId
    author_type: ActorType
    # Provenance recorded by the store, not a claim of authority. For an employee author the
    # store binds this to the authenticated requester; for other actor types it names an
    # agent or runtime component. Nothing downstream may read authorization out of it.
    author_id: str = Field(min_length=1, max_length=AUTHOR_ID_MAX_LENGTH)
    # Untrusted for the same reasons as Ticket.subject, and bounded for the same reasons.
    body: str = Field(min_length=1, max_length=BODY_MAX_LENGTH)
    created_at: AwareDatetime


# Legal status transitions, declared as a permit-list rather than as conditionals spread
# through the store. A move that does not appear here is refused, so anything unanticipated
# is denied instead of allowed (NIST SP 800-162: policy must be complete, with implicit deny
# for unmatched requests). No status lists itself, so a no-op restatement of the current
# status is refused too.
LEGAL_TICKET_TRANSITIONS: Final[Mapping[TicketStatus, frozenset[TicketStatus]]] = {
    TicketStatus.OPEN: frozenset(
        {
            TicketStatus.AWAITING_INFO,
            TicketStatus.PENDING_APPROVAL,
            TicketStatus.RESOLVED,
            TicketStatus.REJECTED,
        }
    ),
    TicketStatus.AWAITING_INFO: frozenset(
        {
            TicketStatus.OPEN,
            TicketStatus.PENDING_APPROVAL,
            TicketStatus.RESOLVED,
            TicketStatus.REJECTED,
        }
    ),
    # A ticket waiting on a human decision leaves only through that decision. Routes back to
    # OPEN or AWAITING_INFO are deliberately absent until the approval state machine defines
    # what an expired or superseded approval does to the ticket it is attached to.
    TicketStatus.PENDING_APPROVAL: frozenset({TicketStatus.RESOLVED, TicketStatus.REJECTED}),
    TicketStatus.RESOLVED: frozenset(),
    TicketStatus.REJECTED: frozenset(),
}

# Derived from the table rather than listed again, so the two cannot disagree.
TERMINAL_TICKET_STATUSES: Final[frozenset[TicketStatus]] = frozenset(
    status for status, reachable in LEGAL_TICKET_TRANSITIONS.items() if not reachable
)
