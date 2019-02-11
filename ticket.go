package security

import (
	"time"

	"github.com/zaddok/log"
)

type TicketManager interface {
	// GetTicket looks up a parentless ticket by ticked uuid
	GetTicket(uuid string, requestor Session) (Ticket, error)

	// GetTicketWithParent looks up a ticket by uuid with a specfic parent object
	GetTicketWithParent(parentType, parentUuid, uuid string, requestor Session) (Ticket, error)

	GetTicketsByStatus(status string, requestor Session) ([]Ticket, error)
	GetTicketsByEmail(email string, requestor Session) ([]Ticket, error)
	GetTicketsByPersonUuid(personUuid string, requestor Session) ([]Ticket, error)
	GetTicketsByParentUuid(parentType, parentUuid string, requestor Session) ([]Ticket, error)
	GetTicketsByStatusParentUuid(status, parentType, parentUuid string, requestor Session) ([]Ticket, error)

	GetTicketResponses(uuid string) ([]TicketResponse, error)

	SearchTickets(keyword string, requestor Session) ([]Ticket, error)

	AddTicketWithParent(parentType, parentUuid, status, personUuid, firstName, lastName, email, ticketType, subject, message, ip string, tags []string, assignedTo, watchedBy []TicketViewer, userAgent string, requestor Session) (Ticket, error)
	AddTicket(status, personUuid, firstName, lastName, email, ticketType, subject, message, ip string, tags []string, assignedTo, watchedBy []TicketViewer, userAgent string, requestor Session) (Ticket, error)
	AddTicketResponse(response TicketResponse, requestor Session) error

	Log() log.Log
	Setting() Setting
	PicklistStore() PicklistStore
}

// Information about a support ticket
type Ticket interface {
	GetUuid() string
	GetStatus() string     // Open, Closed
	GetPersonUuid() string // If signed in, this is the person that initiated the ticket
	GetFirstName() string
	GetLastName() string
	GetEmail() string
	GetSubject() string
	GetType() string // New Feature, Bug, Enhancement, etc...
	GetMessage() string
	GetIP() string
	GetTags() []string
	GetResponseCount() int64
	GetAssignedTo() []TicketViewer
	GetWatchedBy() []TicketViewer
	GetUserAgent() string
	GetCreated() time.Time
}

type TicketViewer struct {
	Uuid        string
	DisplayName string
}

// Information about a support ticket
type TicketResponse interface {
	GetUuid() string
	GetTicketUuid() string
	GetPersonUuid() string // Person who created this response
	GetPersonDisplayName() string
	GetStatus() string // Respondant selected this status
	GetSubject() string
	GetMessage() string
	GetIP() string
	GetUserAgent() string
	GetCreated() time.Time
}
