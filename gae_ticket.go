package security

import (
	"context"
	"errors"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

// Information about a support ticket
type GaeTicket struct {
	parentType    string
	parentUuid    string
	uuid          string
	ticketType    TicketType
	status        TicketStatus
	personUuid    string
	firstName     string
	lastName      string
	email         string
	subject       string
	message       string
	ip            string
	tags          []string
	assignedTo    []TicketViewer
	watchedBy     []TicketViewer
	userAgent     string
	responseCount int64
	created       *time.Time
	actionAfter   *time.Time
}

func (t *GaeTicket) ParentType() string {
	return t.parentType
}

func (t *GaeTicket) ParentUuid() string {
	return t.parentUuid
}

func (t *GaeTicket) Uuid() string {
	return t.uuid
}

func (t *GaeTicket) Status() TicketStatus {
	return t.status
}

func (t *GaeTicket) Type() TicketType {
	return t.ticketType
}

func (t *GaeTicket) PersonUuid() string {
	return t.personUuid
}

func (t *GaeTicket) FirstName() string {
	return t.firstName
}

func (t *GaeTicket) LastName() string {
	return t.lastName
}

func (t *GaeTicket) Email() string {
	return t.email
}

func (t *GaeTicket) Subject() string {
	return t.subject
}

func (t *GaeTicket) Message() string {
	return t.message
}

func (t *GaeTicket) IP() string {
	return t.ip
}

func (t *GaeTicket) Tags() []string {
	return t.tags
}

func (t *GaeTicket) ResponseCount() int64 {
	return t.responseCount
}

func (t *GaeTicket) AssignedTo() []TicketViewer {
	return t.assignedTo
}

func (t *GaeTicket) WatchedBy() []TicketViewer {
	return t.watchedBy
}

func (t *GaeTicket) UserAgent() string {
	return t.userAgent
}

func (t *GaeTicket) Created() *time.Time {
	return t.created
}

func (t *GaeTicket) ActionAfter() *time.Time {
	return t.actionAfter
}

// Information about a support ticket
type GaeTicketResponse struct {
	uuid              string
	status            TicketStatus
	ticketUuid        string
	personUuid        string
	personDisplayName string
	subject           string
	message           string
	ip                string
	userAgent         string
	created           *time.Time
}

func (r *GaeTicketResponse) Uuid() string {
	return r.uuid
}

func (r *GaeTicketResponse) Status() TicketStatus {
	return r.status
}

func (r *GaeTicketResponse) TicketUuid() string {
	return r.ticketUuid
}

func (r *GaeTicketResponse) PersonUuid() string {
	return r.personUuid
}

func (r *GaeTicketResponse) PersonDisplayName() string {
	return r.personDisplayName
}

func (r *GaeTicketResponse) Subject() string {
	return r.subject
}

func (r *GaeTicketResponse) Message() string {
	return r.message
}

func (r *GaeTicketResponse) IP() string {
	return r.ip
}

func (r *GaeTicketResponse) UserAgent() string {
	return r.userAgent
}

func (r *GaeTicketResponse) Created() *time.Time {
	return r.created
}

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
func (t *GaeTicketManager) GetTicket(uuid string, session Session) (Ticket, error) {
	k := datastore.NameKey("Ticket", uuid, nil)
	k.Namespace = session.Site()

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
func (t *GaeTicketManager) GetTicketWithParent(parentType, parentUuid, uuid string, session Session) (Ticket, error) {
	pk := datastore.NameKey(parentType, parentUuid, nil)
	pk.Namespace = session.Site()

	k := datastore.NameKey("Ticket", uuid, pk)
	k.Namespace = session.Site()

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
func (t *GaeTicketManager) GetTicketsByStatus(status TicketStatus, session Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(session.Site()).Filter("Status =", string(status)).Order("-Created").Limit(200)
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
func (t *GaeTicketManager) GetTicketsByEmail(email string, session Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(session.Site()).Filter("Email =", email).Order("-Created").Limit(200)
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
func (t *GaeTicketManager) GetTicketsByPersonUuid(personUuid string, session Session) ([]Ticket, error) {
	var tickets []Ticket

	q := datastore.NewQuery("Ticket").Namespace(session.Site()).Filter("PersonUuid =", personUuid).Order("-Created").Limit(200)
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
func (t *GaeTicketManager) GetTicketsByParentRecord(parentType, parentUuid string, session Session) ([]Ticket, error) {
	var tickets []Ticket

	pkey := datastore.NameKey(parentType, parentUuid, nil)
	pkey.Namespace = session.Site()

	q := datastore.NewQuery("Ticket").Namespace(session.Site()).Ancestor(pkey).Order("-Created").Limit(200)
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
func (t *GaeTicketManager) GetTicketsByStatusParentRecord(status TicketStatus, parentType, parentUuid string, session Session) ([]Ticket, error) {
	var tickets []Ticket

	pkey := datastore.NameKey(parentType, parentUuid, nil)
	pkey.Namespace = session.Site()

	q := datastore.NewQuery("Ticket").Namespace(session.Site()).Ancestor(pkey).Filter("Status =", string(status)).Order("-Created").Limit(200)
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

func (t *GaeTicketManager) SearchTickets(keyword string, session Session) ([]Ticket, error) {
	var tickets []Ticket

	return tickets, nil
}

func (t *GaeTicketManager) AddTicket(status TicketStatus, ticketType TicketType, personUuid, firstName, lastName, email, subject, message string, actionAfter *time.Time, tags []string, assignedTo, watchedBy []TicketViewer, session Session) (Ticket, error) {
	return t.AddTicketWithParent("", "", status, ticketType, personUuid, firstName, lastName, email, subject, message, actionAfter, tags, assignedTo, watchedBy, session)
}

func (t *GaeTicketManager) AddTicketWithParent(parentType, parentUuid string, status TicketStatus, ticketType TicketType, personUuid, firstName, lastName, email, subject, message string, actionAfter *time.Time, tags []string, assignedTo, watchedBy []TicketViewer, session Session) (Ticket, error) {
	var ticket GaeTicket

	uuid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	now := time.Now()

	ticket.uuid = uuid.String()
	ticket.status = status
	ticket.ticketType = ticketType
	ticket.personUuid = personUuid
	ticket.firstName = firstName
	ticket.lastName = lastName
	ticket.email = email
	ticket.subject = subject
	ticket.message = message
	ticket.actionAfter = actionAfter
	ticket.tags = tags
	ticket.assignedTo = assignedTo
	ticket.watchedBy = watchedBy
	ticket.ip = session.IP()
	ticket.userAgent = session.UserAgent()
	ticket.created = &now

	var pk *datastore.Key = nil
	if parentType != "" && parentUuid != "" {
		pk = datastore.NameKey(parentType, parentUuid, nil)
		pk.Namespace = session.Site()
	}

	k := datastore.NameKey("Ticket", ticket.uuid, pk)
	k.Namespace = session.Site()
	if _, err := t.client.Put(t.ctx, k, &ticket); err != nil {
		t.am.Error(session, `ticket`, "AddTicket() failed. Error: %v", err)
		return nil, err
	}

	err = t.am.TriggerNotificationEvent(session.Site()+"."+string(ticketType), session)
	if err != nil {
		//TODO: What should we do here?
		return &ticket, nil
	}

	return &ticket, nil
}

// AddTicketResponse adds a child record to the datastore containing a response. The status of the parent ticket will be updated if required. Subject and Message fields are optional.
func (t *GaeTicketManager) AddTicketResponse(ticketUuid string, status TicketStatus, subject, message string, session Session) error {
	return t.AddParentedTicketResponse("", "", ticketUuid, status, subject, message, session)
}

// AddTicketResponse adds a child record to the datastore containing a response. The status of the parent ticket will be updated if required. Subject and Message fields are optional.
func (t *GaeTicketManager) AddParentedTicketResponse(recordType string, recordUuid string, ticketUuid string, status TicketStatus, subject, message string, session Session) error {
	if session == nil {
		return errors.New("Session variable must be specified")
	}

	now := time.Now()
	uuid, err := uuid.NewUUID()
	if err != nil {
		return err
	}

	pk := datastore.NameKey("Ticket", ticketUuid, nil)
	pk.Namespace = session.Site()

	if recordType != "" {
		ak := datastore.NameKey(recordType, recordUuid, nil)
		ak.Namespace = session.Site()
		pk = datastore.NameKey("Ticket", ticketUuid, ak)
		pk.Namespace = session.Site()
	}

	// Ticket is fetched to check if the ticket status has been changed, and to update the response counter
	_, err = t.client.RunInTransaction(t.ctx, func(tx *datastore.Transaction) error {

		var ticket GaeTicket
		err = tx.Get(pk, &ticket)
		if err == datastore.ErrNoSuchEntity {
			return err
		} else if err != nil {
			return err
		}

		if ticket.status == status && message == "" && subject == "" {
			// There is literally nothing to save
			return nil
		}

		// If ticket status has changed, parent must be updated
		ticket.status = status
		ticket.responseCount = ticket.responseCount + 1
		if _, err := tx.Put(pk, &ticket); err != nil {
			return err
		}

		k := datastore.NameKey("TicketResponse", uuid.String(), pk)
		k.Namespace = session.Site()

		var response GaeTicketResponse
		response.uuid = uuid.String()
		response.ticketUuid = ticket.uuid
		response.status = status
		response.subject = subject
		response.message = message
		response.created = &now
		response.userAgent = session.UserAgent()
		response.ip = session.IP()
		_, err := tx.Put(k, &response)
		return err
	})
	if err != nil {
		t.am.Error(session, `ticket`, "AddTicketResponse() failed. Error: %v", err)
		return err
	}

	return nil
}

func (t *GaeTicketManager) Setting() Setting {
	return t.am.Setting()
}

func (t *GaeTicketManager) PicklistStore() PicklistStore {
	return t.am.PicklistStore()
}

func (p *GaeTicket) LoadKey(k *datastore.Key) error {
	if k != nil && k.Parent != nil {
		p.parentType = k.Parent.Kind
		p.parentUuid = k.Parent.Name
	}
	return nil
}

func (p *GaeTicket) Load(ps []datastore.Property) error {
	for _, i := range ps {
		switch i.Name {
		case "UUID", "Uuid":
			p.uuid = i.Value.(string)
			break
		case "Type":
			p.ticketType = TicketType(i.Value.(string))
			break
		case "Status":
			p.status = TicketStatus(i.Value.(string))
			break
		case "PersonUUID", "PersonUuid":
			p.personUuid = i.Value.(string)
			break
		case "FirstName":
			p.firstName = i.Value.(string)
			break
		case "LastName":
			p.lastName = i.Value.(string)
			break
		case "Email":
			p.email = i.Value.(string)
			break
		case "IP":
			p.ip = i.Value.(string)
			break
		case "UserAgent":
			p.userAgent = i.Value.(string)
			break
		case "Subject":
			p.subject = i.Value.(string)
			break
		case "Message":
			p.message = i.Value.(string)
			break
		case "Tags":
			p.tags = strings.Split(i.Value.(string), "|")
			break
		case "Created":
			if i.Value != nil {
				t := i.Value.(time.Time)
				p.created = &t
			}
			break
		case "ActionAfter":
			if i.Value != nil {
				t := i.Value.(time.Time)
				p.actionAfter = &t
			}
			break
		}
	}
	return nil
}

func (p *GaeTicket) Save() ([]datastore.Property, error) {
	props := []datastore.Property{
		{
			Name:  "UUID",
			Value: p.uuid,
		},
		{
			Name:  "Type",
			Value: string(p.ticketType),
		},
		{
			Name:  "Status",
			Value: string(p.status),
		},
		{
			Name:  "PersonUUID",
			Value: p.personUuid,
		},
		{
			Name:  "FirstName",
			Value: p.firstName,
		},
		{
			Name:  "LastName",
			Value: p.lastName,
		},
		{
			Name:  "Email",
			Value: p.email,
		},
		{
			Name:  "IP",
			Value: p.ip,
		},
		{
			Name:  "UserAgent",
			Value: p.userAgent,
		},
		{
			Name:  "Subject",
			Value: p.subject,
		},
		{
			Name:  "Message",
			Value: p.message,
		},
	}

	if len(p.tags) > 0 {
		props = append(props, datastore.Property{Name: "Tags", Value: strings.Join(p.tags, "|")})
	}
	if p.created != nil {
		props = append(props, datastore.Property{Name: "Created", Value: p.created})
	}
	if p.actionAfter != nil {
		props = append(props, datastore.Property{Name: "ActionAfter", Value: p.actionAfter})
	}

	return props, nil
}

func (p *GaeTicketResponse) Load(ps []datastore.Property) error {
	for _, i := range ps {
		switch i.Name {
		case "UUID", "Uuid":
			p.uuid = i.Value.(string)
			break
		case "Status":
			p.status = TicketStatus(i.Value.(string))
			break
		case "TicketUUID", "TicketUuid":
			p.ticketUuid = i.Value.(string)
			break
		case "PersonUUID", "PersonUuid":
			p.personUuid = i.Value.(string)
			break
		case "IP":
			p.ip = i.Value.(string)
			break
		case "UserAgent":
			p.userAgent = i.Value.(string)
			break
		case "Subject":
			p.subject = i.Value.(string)
			break
		case "Message":
			p.message = i.Value.(string)
			break
		case "Created":
			if i.Value != nil {
				t := i.Value.(time.Time)
				p.created = &t
			}
			break
		}
	}
	return nil
}

func (p *GaeTicketResponse) Save() ([]datastore.Property, error) {
	props := []datastore.Property{
		{
			Name:  "UUID",
			Value: p.uuid,
		},
		{
			Name:  "TicketUUID",
			Value: p.ticketUuid,
		},
		{
			Name:  "Status",
			Value: string(p.status),
		},
		{
			Name:  "PersonUUID",
			Value: p.personUuid,
		},
		{
			Name:  "PersonDisplayName",
			Value: p.personDisplayName,
		},
		{
			Name:  "Subject",
			Value: p.subject,
		},
		{
			Name:  "Message",
			Value: p.message,
		},
		{
			Name:  "IP",
			Value: p.ip,
		},
		{
			Name:  "UserAgent",
			Value: p.userAgent,
		},
	}

	if p.created != nil {
		props = append(props, datastore.Property{Name: "Created", Value: p.created})
	}

	return props, nil
}
