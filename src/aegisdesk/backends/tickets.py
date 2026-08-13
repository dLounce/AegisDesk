from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Protocol

from aegisdesk.domain.enums import ActorType, TicketStatus
from aegisdesk.domain.errors import (
    CrossEmployeeAccessError,
    IllegalTicketTransitionError,
    TicketNotFoundError,
)
from aegisdesk.domain.ids import EmployeeId, TicketId
from aegisdesk.domain.ticket import LEGAL_TICKET_TRANSITIONS, Ticket, TicketMessage


# Every operation takes the authenticated requester as its first argument, so the store
# cannot be called without stating who is asking and scoping is decided here rather than by
# a caller that might forget. The identity must come from trusted session context: never
# from ticket text, message bodies, or model output.
class TicketStore(Protocol):
    def create(self, requester_id: EmployeeId, subject: str) -> Ticket: ...

    def get(self, requester_id: EmployeeId, ticket_id: TicketId) -> Ticket: ...

    def messages(
        self, requester_id: EmployeeId, ticket_id: TicketId
    ) -> Sequence[TicketMessage]: ...

    def append_message(
        self,
        requester_id: EmployeeId,
        ticket_id: TicketId,
        author_type: ActorType,
        author_id: str,
        body: str,
    ) -> TicketMessage: ...

    def set_status(
        self, requester_id: EmployeeId, ticket_id: TicketId, new_status: TicketStatus
    ) -> Ticket: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


class InMemoryTicketStore(TicketStore):
    def __init__(self, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock
        self._tickets: dict[TicketId, Ticket] = {}
        self._messages: dict[TicketId, list[TicketMessage]] = {}
        self._next_number = 1

    def create(self, requester_id: EmployeeId, subject: str) -> Ticket:
        now = self._clock()
        ticket = Ticket(
            ticket_id=TicketId(f"IT-{self._next_number:04d}"),
            requester_id=requester_id,
            subject=subject,
            status=TicketStatus.OPEN,
            created_at=now,
            updated_at=now,
        )
        self._next_number += 1
        self._tickets[ticket.ticket_id] = ticket
        self._messages[ticket.ticket_id] = []
        return ticket

    def get(self, requester_id: EmployeeId, ticket_id: TicketId) -> Ticket:
        return self._owned(requester_id, ticket_id)

    def messages(self, requester_id: EmployeeId, ticket_id: TicketId) -> Sequence[TicketMessage]:
        ticket = self._owned(requester_id, ticket_id)
        # A tuple, so a caller cannot append to the stored thread through the value it was
        # handed back.
        return tuple(self._messages[ticket.ticket_id])

    def append_message(
        self,
        requester_id: EmployeeId,
        ticket_id: TicketId,
        author_type: ActorType,
        author_id: str,
        body: str,
    ) -> TicketMessage:
        ticket = self._owned(requester_id, ticket_id)
        # An employee-authored message is bound to the authenticated requester. Taking the
        # author id from the caller instead would let whoever composes the call choose whose
        # words these are, which is the identity claim that is never trusted.
        if author_type is ActorType.EMPLOYEE and author_id != requester_id:
            raise CrossEmployeeAccessError(
                f"requester {requester_id} may not author a message as another employee"
            )
        # Built before anything is stored so a rejected body leaves no partial write behind.
        message = TicketMessage(
            ticket_id=ticket.ticket_id,
            author_type=author_type,
            author_id=author_id,
            body=body,
            created_at=self._clock(),
        )
        self._messages[ticket.ticket_id].append(message)
        self._save(ticket, ticket.status)
        return message

    def set_status(
        self, requester_id: EmployeeId, ticket_id: TicketId, new_status: TicketStatus
    ) -> Ticket:
        # Ownership resolves first. An illegal-transition error raised for someone else's
        # ticket would confirm both that the ticket exists and what state it is in.
        ticket = self._owned(requester_id, ticket_id)
        # A status missing from the table yields an empty set, so an incomplete table denies
        # rather than raising KeyError on a path that is meant to fail closed.
        #
        # new_status is the untrusted argument and is formatted without .value: a raw string
        # never matches a plain-Enum member, so it lands here, and reaching for .value on it
        # would replace this error with an AttributeError.
        if new_status not in LEGAL_TICKET_TRANSITIONS.get(ticket.status, frozenset()):
            raise IllegalTicketTransitionError(
                f"{ticket.status.value} -> {new_status!r} is not a legal ticket transition"
            )
        return self._save(ticket, new_status)

    # The error text is identical whether the ticket is missing or belongs to someone else,
    # and names neither the ticket nor its owner, so failures cannot be compared to discover
    # which ticket ids are real.
    def _owned(self, requester_id: EmployeeId, ticket_id: TicketId) -> Ticket:
        ticket = self._tickets.get(ticket_id)
        if ticket is None or ticket.requester_id != requester_id:
            raise TicketNotFoundError(f"requester {requester_id} has no ticket with that id")
        return ticket

    # Ticket is frozen, so every change is a replacement. Both mutating paths go through
    # here, which is what keeps updated_at from being maintained on one and forgotten on the
    # other.
    def _save(self, ticket: Ticket, status: TicketStatus) -> Ticket:
        updated = Ticket(
            ticket_id=ticket.ticket_id,
            requester_id=ticket.requester_id,
            subject=ticket.subject,
            status=status,
            created_at=ticket.created_at,
            updated_at=self._clock(),
        )
        self._tickets[ticket.ticket_id] = updated
        return updated
