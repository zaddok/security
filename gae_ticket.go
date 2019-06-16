package security

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

func NewGaeTicketManager(client *datastore.Client, ctx context.Context, am AccessManager) *GaeTicketManager {
	s := &GaeTicketManager{
		client: client,
		ctx:    ctx,
		am:     am,
	}
	return s
}

type GaeTicketManager struct {
	client *datastore.Client
	ctx    context.Context
	am     AccessManager
}

// GetTicket looks up a parentless ticket by ticked uuid
func (t *GaeTicketManager) GetTicket(uuid string, requestor Session) (Ticket, error) {
	k := datastore.NameKey("Ticket", uuid, nil)
	k.Namespace = requestor.Site()

	var ticket GaeTicket
	err := t.client.Get(t.ctx, k, &ticket)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &ticket, nil
}

// GetTicketWithParent looks up a ticket by uuid with a specfic parent object
func (t *GaeTicketManager) GetTicketWithParent(parentType, parentUuid, uuid string, requestor Session) (Ticket, error) {
	pk := datastore.NameKey(parentType, parentUuid, nil)
	pk.Namespace = requestor.Site()

	k := datastore.NameKey("Ticket", uuid, pk)
	k.Namespace = requestor.Site()

	var ticket GaeTicket
	err := t.client.Get(t.ctx, k, &ticket)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &ticket, nil
}

// GetTicketsByStatus returns all tickets with this status. For example: list all open tickets in the system.
func (t *GaeTicketManager) GetTicketsByStatus(status string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(requestor.Site()).Filter("Status =", status).Order("-Created").Limit(200)
	it := t.client.Run(t.ctx, q)
	for {
		e := new(GaeTicket)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		tickets = append(tickets, e)
	}

	return tickets[:], nil
}

// GetTicketsByEmail returns all tickets created by a specific person with this specific email address
func (t *GaeTicketManager) GetTicketsByEmail(email string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(requestor.Site()).Filter("Email =", email).Order("-Created").Limit(200)
	it := t.client.Run(t.ctx, q)
	for {
		e := new(GaeTicket)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		tickets = append(tickets, e)
	}

	return tickets[:], nil
}

// GetTicketsByPersonUuid returns all tickets created by a specific person
func (t *GaeTicketManager) GetTicketsByPersonUuid(personUuid string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(requestor.Site()).Filter("PersonUuid =", personUuid).Order("-Created").Limit(200)
	it := t.client.Run(t.ctx, q)
	for {
		e := new(GaeTicket)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		tickets = append(tickets, e)
	}

	return tickets, nil
}

// GetTicketsByParentUuid returns all ticket
func (t *GaeTicketManager) GetTicketsByParentUuid(parentType, parentUuid string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	pkey := datastore.NameKey(parentType, parentUuid, nil)
	pkey.Namespace = requestor.Site()

	q := datastore.NewQuery("Ticket").Namespace(requestor.Site()).Ancestor(pkey).Order("-Created").Limit(200)
	it := t.client.Run(t.ctx, q)
	for {
		e := new(GaeTicket)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		tickets = append(tickets, e)
	}

	return tickets, nil
}
func (t *GaeTicketManager) GetTicketsByStatusParentUuid(status, parentType, parentUuid string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	pkey := datastore.NameKey(parentType, parentUuid, nil)
	pkey.Namespace = requestor.Site()

	q := datastore.NewQuery("Ticket").Namespace(requestor.Site()).Ancestor(pkey).Filter("Status =", status).Order("-Created").Limit(200)
	it := t.client.Run(t.ctx, q)
	for {
		e := new(GaeTicket)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		tickets = append(tickets, e)
	}

	return tickets, nil
}

func (t *GaeTicketManager) GetTicketResponses(uuid string) ([]TicketResponse, error) {
	var responses []TicketResponse

	return responses, nil
}

func (t *GaeTicketManager) SearchTickets(keyword string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	return tickets, nil
}

func (t *GaeTicketManager) AddTicket(status, personUuid, firstName, lastName, email, ticketType, subject, message, ip string, tags []string, assignedTo, watchedBy []TicketViewer, userAgent string, requestor Session) (Ticket, error) {
	return t.AddTicketWithParent("", "", status, personUuid, firstName, lastName, email, ticketType, subject, message, ip, tags, assignedTo, watchedBy, userAgent, requestor)
}

func (t *GaeTicketManager) AddTicketWithParent(parentType, parentUuid, status, personUuid, firstName, lastName, email, ticketType, subject, message, ip string, tags []string, assignedTo, watchedBy []TicketViewer, userAgent string, requestor Session) (Ticket, error) {
	var ticket GaeTicket

	uuid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}

	ticket.Uuid = uuid.String()
	ticket.Status = status
	ticket.PersonUuid = personUuid
	ticket.FirstName = firstName
	ticket.LastName = lastName
	ticket.Email = email
	ticket.Subject = subject
	ticket.Type = ticketType
	ticket.Message = message
	ticket.IP = ip
	ticket.Tags = tags
	ticket.AssignedTo = assignedTo
	ticket.WatchedBy = watchedBy
	ticket.UserAgent = userAgent
	ticket.Created = time.Now()

	var pk *datastore.Key = nil
	if parentType != "" && parentUuid != "" {
		pk = datastore.NameKey(parentType, parentUuid, nil)
		pk.Namespace = requestor.Site()
	}

	k := datastore.NameKey("Ticket", ticket.Uuid, pk)
	k.Namespace = requestor.Site()
	if _, err := t.client.Put(t.ctx, k, &ticket); err != nil {
		t.am.Error(requestor, `ticket`, "AddTicket() failed. Error: %v", err)
		return nil, err
	}

	return &ticket, nil
}

func (t *GaeTicketManager) AddTicketResponse(response TicketResponse, requestor Session) error {
	return nil
}

func (t *GaeTicketManager) Setting() Setting {
	return t.am.Setting()
}

func (t *GaeTicketManager) PicklistStore() PicklistStore {
	return t.am.PicklistStore()
}

// Information about a support ticket
type GaeTicket struct {
	Uuid          string
	Status        string
	PersonUuid    string
	FirstName     string
	LastName      string
	Email         string
	Type          string
	Subject       string
	Message       string
	IP            string
	Tags          []string
	AssignedTo    []TicketViewer
	WatchedBy     []TicketViewer
	UserAgent     string
	ResponseCount int64
	Created       time.Time
}

func (t *GaeTicket) GetUuid() string {
	return t.Uuid
}
func (t *GaeTicket) GetStatus() string {
	return t.Status
}
func (t *GaeTicket) GetPersonUuid() string {
	return t.PersonUuid
}
func (t *GaeTicket) GetFirstName() string {
	return t.FirstName
}
func (t *GaeTicket) GetLastName() string {
	return t.LastName
}
func (t *GaeTicket) GetEmail() string {
	return t.Email
}
func (t *GaeTicket) GetType() string {
	return t.Type
}
func (t *GaeTicket) GetSubject() string {
	return t.Subject
}
func (t *GaeTicket) GetMessage() string {
	return t.Message
}
func (t *GaeTicket) GetIP() string {
	return t.IP
}
func (t *GaeTicket) GetTags() []string {
	return t.Tags
}
func (t *GaeTicket) GetResponseCount() int64 {
	return t.ResponseCount
}
func (t *GaeTicket) GetAssignedTo() []TicketViewer {
	return t.AssignedTo
}
func (t *GaeTicket) GetWatchedBy() []TicketViewer {
	return t.WatchedBy
}
func (t *GaeTicket) GetUserAgent() string {
	return t.UserAgent
}
func (t *GaeTicket) GetCreated() time.Time {
	return t.Created
}

// Information about a support ticket
type GaeTicketResponse struct {
	Uuid              string
	TicketUuid        string
	PersonUuid        string
	PersonDisplayName string
	Status            string
	Subject           string
	Message           string
	IP                string
	UserAgent         string
	Created           time.Time
}

func (r *GaeTicketResponse) GetUuid() string {
	return r.Uuid
}

func (r *GaeTicketResponse) GetTicketUuid() string {
	return r.TicketUuid
}

func (r *GaeTicketResponse) GetPersonUuid() string {
	return r.PersonUuid
}

func (r *GaeTicketResponse) GetPersonDisplayName() string {
	return r.PersonDisplayName
}

func (r *GaeTicketResponse) GetStatus() string {
	return r.Status
}

func (r *GaeTicketResponse) GetSubject() string {
	return r.Subject
}

func (r *GaeTicketResponse) GetMessage() string {
	return r.Message
}

func (r *GaeTicketResponse) GetIP() string {
	return r.IP
}

func (r *GaeTicketResponse) GetUserAgent() string {
	return r.UserAgent
}

func (r *GaeTicketResponse) GetCreated() time.Time {
	return r.Created
}
