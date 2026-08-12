from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from aegisdesk.domain.enums import TicketStatus
from aegisdesk.domain.ids import EmployeeId, TicketId

SUBJECT_MAX_LENGTH = 200


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
