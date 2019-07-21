package security

import (
	"time"
)

type TicketManager interface {
	// GetTicket looks up a parentless ticket by ticked uuid
	GetTicket(uuid string, session Session) (Ticket, error)

	// GetTicketWithParent looks up a ticket by uuid with a specfic parent object
	GetTicketWithParent(parentType, parentUuid, uuid string, session Session) (Ticket, error)

	GetTicketsByStatus(status TicketStatus, session Session) ([]Ticket, error)
	GetTicketsByEmail(email string, session Session) ([]Ticket, error)
	GetTicketsByPersonUuid(personUuid string, session Session) ([]Ticket, error)
	GetTicketsByParentRecord(parentType, parentUuid string, session Session) ([]Ticket, error)
	GetTicketsByStatusParentRecord(status TicketStatus, recordType, recordUuid string, session Session) ([]Ticket, error)

	GetTicketResponses(uuid string) ([]TicketResponse, error)

	SearchTickets(keyword string, session Session) ([]Ticket, error)

	AddTicket(status TicketStatus, ticketType TicketType, personUuid, firstName, lastName, email, subject, message string, tags []string, assignedTo, watchedBy []TicketViewer, session Session) (Ticket, error)
	AddTicketWithParent(parentType, parentUuid string, status TicketStatus, ticketType TicketType, personUuid, firstName, lastName, email, subject, message string, tags []string, assignedTo, watchedBy []TicketViewer, session Session) (Ticket, error)
	AddTicketResponse(ticketUuid string, status TicketStatus, subject, message string, session Session) error
	AddParentedTicketResponse(recordType string, recordUuid string, ticketUuid string, status TicketStatus, subject, message string, session Session) error

	Setting() Setting
	PicklistStore() PicklistStore
}

type TicketStatus string

const (
	TicketOpen     TicketStatus = "open"
	TicketArchived TicketStatus = "archived"
	TicketDeleted  TicketStatus = "deleted"
)

type TicketType string

const (
	CourseEnrolmentTicket  TicketType = "course"
	SubjectEnrolmentTicket TicketType = "subject"
	EnquiryTicket          TicketType = "enquiry"
	AcademicTicket         TicketType = "academic"
	TechnicalSupportTicket TicketType = "support"
)

// Information about a support ticket
type Ticket interface {
	Uuid() string
	Type() TicketType
	Status() TicketStatus

	PersonUuid() string // PersonUuid is set if this ticket was raised by an authenticated person

	FirstName() string // FirstName is set if this ticket was raised by a non authenticated person
	LastName() string  // LastName is set if this tickt was raised by a non authenticated person
	Email() string     // Email is set if this ticket was raised by a non authenticated person

	IP() string
	UserAgent() string

	Subject() string
	Message() string
	Tags() []string
	ResponseCount() int64
	AssignedTo() []TicketViewer
	WatchedBy() []TicketViewer
	Created() *time.Time
	ActionAfter() *time.Time
}

type TicketViewer struct {
	Uuid        string
	DisplayName string
}

// Information about a support ticket
type TicketResponse interface {
	Uuid() string
	Status() TicketStatus // Respondant selected this status
	TicketUuid() string
	PersonUuid() string // Person who created this response
	PersonDisplayName() string
	Subject() string // Optional subject for response
	Message() string // Optional message for response

	IP() string
	UserAgent() string
	Created() *time.Time
}
