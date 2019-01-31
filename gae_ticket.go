package security

import (
	"context"
	"time"

	"github.com/zaddok/log"

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

func (t *GaeTicketManager) GetTicket(uuid string, requestor Session) (Ticket, error) {

	k := datastore.NameKey("Ticket", uuid, nil)
	k.Namespace = requestor.GetSite()

	var ticket GaeTicket
	err := t.client.Get(t.ctx, k, &ticket)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &ticket, nil
}

func (t *GaeTicketManager) GetTicketsByStatus(status string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(requestor.GetSite()).Filter("Status =", status).Order("-Created").Limit(200)
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

func (t *GaeTicketManager) GetTicketsByEmail(email string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(requestor.GetSite()).Filter("Email =", email).Order("-Created").Limit(200)
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

func (t *GaeTicketManager) GetTicketsByPersonUuid(personUuid string, requestor Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(requestor.GetSite()).Filter("PersonUuid =", personUuid).Order("-Created").Limit(200)
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

func (t *GaeTicketManager) AddTicket(status, personUuid, firstName, lastName, email, subject, message, ip string, tags []string, assignedTo, watchedBy []TicketViewer, userAgent string, requestor Session) (Ticket, error) {
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
	ticket.Message = message
	ticket.IP = ip
	ticket.Tags = tags
	ticket.AssignedTo = assignedTo
	ticket.WatchedBy = watchedBy
	ticket.UserAgent = userAgent
	ticket.Created = time.Now()

	k := datastore.NameKey("Ticket", ticket.Uuid, nil)
	k.Namespace = requestor.GetSite()
	if _, err := t.client.Put(t.ctx, k, &ticket); err != nil {
		t.Log().Error("AddTicket() failed. Error: %v", err)
		return nil, err
	}

	return &ticket, nil
}

func (t *GaeTicketManager) AddTicketResponse(response TicketResponse, requestor Session) error {
	return nil
}

func (t *GaeTicketManager) Log() log.Log {
	return t.am.Log()
}

func (t *GaeTicketManager) Setting() Setting {
	return t.am.Setting()
}

func (t *GaeTicketManager) PicklistStore() PicklistStore {
	return t.am.PicklistStore()
}

// Information about a support ticket
type GaeTicket struct {
	Uuid       string
	Status     string
	PersonUuid string
	FirstName  string
	LastName   string
	Email      string
	Subject    string
	Message    string
	IP         string
	Tags       []string
	AssignedTo []TicketViewer
	WatchedBy  []TicketViewer
	UserAgent  string
	Created    time.Time
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
