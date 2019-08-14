package security

import (
	"testing"
	"time"

	"github.com/zaddok/log"
)

func TestTicketManager(t *testing.T) {

	l := log.NewStdoutLogDebug()
	defer l.Close()

	// Initialize helper API objects
	am, err, client, context := NewGaeAccessManager(projectId, inferLocation(t), time.Now().Location())
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	tm := NewGaeTicketManager(client, context, am)

	// Setup accounts for peopel to participate in the test workflow
	_, err = am.AddPerson(TestSite, "ticketmanager", "tmp", "ticketmanager.tmp1@example.com", "s1:s2:s3:s4:c1:c2:c3:c4:c5:c6", HashPassword("tmpA@9040hi"), "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("AddPerson() failed: %v", err)
	}
	user, _, err := am.Authenticate(TestSite, "ticketmanager.tmp1@example.com", "tmpA@9040hi", "127.0.0.1", "Safari", "en-AU")
	if err != nil {
		t.Fatalf("Authenticate() failed: %v", err)
	}

	// Basic ticket creation
	{
		ticket, err := tm.AddTicket(
			TicketArchived,
			SubjectEnrolmentTicket,
			user.PersonUuid(),
			user.FirstName(),
			user.LastName(),
			user.Email(),
			"Sample subject message",
			"Sample message content to be read by someone",
			nil,
			[]string{"test", "sample"},
			[]TicketViewer{},
			[]TicketViewer{},
			user)
		if err != nil {
			t.Fatalf("tm.AddTicket() failed: %v", err)
		}
		if ticket.Uuid() == "" {
			t.Fatalf("AddTicket() did not return the generated uuid.")
		}
		// Check the ticket is persisted and loaded correctly
		r, err := tm.GetTicket(ticket.Uuid(), user)
		if err != nil {
			t.Fatalf("tm.GetTicket() failed %s", err)
		}
		if r == nil {
			t.Fatalf("tm.GetTicket() returned no response")
		}
		if r.FirstName() != user.FirstName() {
			t.Fatalf("tm.GetTicket() did not return firstname %s. It returned %s", user.FirstName(), r.FirstName())
		}
		if r.Status() != TicketArchived {
			t.Fatalf("tm.GetTicket() did not return status \"%v\". It returned %s", TicketArchived, r.Status())
		}
		if r.Type() != SubjectEnrolmentTicket {
			t.Fatalf("tm.GetTicket() did not return type \"%v\". It returned %s", SubjectEnrolmentTicket, r.Type())
		}
		if r.UserAgent() != ticket.UserAgent() {
			t.Fatalf("tm.GetTicket() did not return user agent \"%s\". It returned %s", ticket.UserAgent(), r.UserAgent())
		}
	}

	// Basic child ticket creation
	uuid2 := ""
	{
		_, err := tm.AddTicketWithParent(
			"Student",
			"uuid1",
			TicketOpen,
			SubjectEnrolmentTicket,
			user.PersonUuid(),
			user.FirstName(),
			user.LastName(),
			user.Email(),
			"Sample subject message",
			"Sample message content to be read by someone",
			nil,
			[]string{"test", "sample"},
			[]TicketViewer{},
			[]TicketViewer{},
			user)
		if err != nil {
			t.Fatalf("tm.AddTicket() failed: %v", err)
		}
		_, err = tm.AddTicketWithParent(
			"Student",
			"uuid1",
			TicketOpen,
			SubjectEnrolmentTicket,
			user.PersonUuid(),
			user.FirstName(),
			user.LastName(),
			user.Email(),
			"Sample subject message",
			"Sample message content to be read by someone",
			nil,
			[]string{"test", "sample"},
			[]TicketViewer{},
			[]TicketViewer{},
			user)
		if err != nil {
			t.Fatalf("tm.AddTicket() failed: %v", err)
		}
		ticket, err := tm.AddTicketWithParent(
			"Student",
			"uuid2",
			TicketOpen,
			SubjectEnrolmentTicket,
			user.PersonUuid(),
			user.FirstName(),
			user.LastName(),
			user.Email(),
			"Sample subject message",
			"Sample message content to be read by someone",
			nil,
			[]string{"test", "sample"},
			[]TicketViewer{},
			[]TicketViewer{},
			user)
		if err != nil {
			t.Fatalf("tm.AddTicket() failed: %v", err)
		}
		uuid2 = ticket.Uuid()

	}

	// There are three open tickets and one archived. Three of which are child tickets of another object
	{
		tickets, err := tm.GetTicketsByStatus(TicketOpen, user)
		if err != nil {
			t.Fatalf("tm.GetTicketsByStatus() failed: %v", err)
		}
		if len(tickets) != 3 {
			t.Fatalf("tm.GetTicketsByStatus() expecting 3 open tickets, not %d", len(tickets))
		}

		// 2 tickets attached to student(uuid1)
		tickets, err = tm.GetTicketsByStatusParentRecord(TicketOpen, "Student", "uuid1", user)
		if err != nil {
			t.Fatalf("tm.GetTicketsByStatus() failed: %v", err)
		}
		if len(tickets) != 2 {
			t.Fatalf("tm.GetTicketsByStatus() expecting 2 open tickets, not %d", len(tickets))
		}

	}

	// There are three open tickets and two archived.
	{
		err := tm.AddParentedTicketResponse("Student", "uuid2", uuid2, TicketArchived, "This is a response", "Body of the response message is here.", user)
		if err != nil {
			t.Fatalf("tm.AddTicketResponse() failed: %v", err)
		}

		tickets, err := tm.GetTicketsByStatus(TicketOpen, user)
		if err != nil {
			t.Fatalf("tm.GetTicketsByStatus() failed: %v", err)
		}
		if len(tickets) != 2 {
			t.Fatalf("tm.GetTicketsByStatus() expecting 2 open tickets, not %d", len(tickets))
		}

		tickets, err = tm.GetTicketsByStatus(TicketArchived, user)
		if err != nil {
			t.Fatalf("tm.GetTicketsByStatus() failed: %v", err)
		}
		if len(tickets) != 2 {
			t.Fatalf("tm.GetTicketsByStatus() expecting 2 archived tickets, not %d", len(tickets))
		}

	}

}
