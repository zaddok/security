package security

import (
	"testing"

	"github.com/zaddok/log"
)

func TestTicketManager(t *testing.T) {

	l := log.NewStdoutLogDebug()
	defer l.Close()

	// Initialize helper API objects
	am, err, client, context := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), l)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	tm := NewGaeTicketManager(client, context, am)

	// Setup accounts for peopel to participate in the test workflow
	_, err = am.AddPerson(TestSite, "ticketmanager", "tmp", "ticketmanager.tmp1@example.com", "s1:s2:s3:s4:c1:c2:c3:c4:c5:c6", HashPassword("tmpA@9040hi"), "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("AddPerson() failed: %v", err)
	}
	user, _, err := am.Authenticate(TestSite, "ticketmanager.tmp1@example.com", "tmpA@9040hi", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate() failed: %v", err)
	}

	// Ticket creation
	{
		ticket, err := tm.AddTicket(
			"open",
			user.GetPersonUuid(),
			user.GetFirstName(),
			user.GetLastName(),
			user.GetEmail(),
			"Sample subject message",
			"Sample message content to be read by someone",
			"127.0.0.1",
			[]string{"test", "sample"},
			[]TicketViewer{},
			[]TicketViewer{},
			"User Agent String",
			user)
		if err != nil {
			t.Fatalf("tm.AddTicket() failed: %v", err)
		}
		if ticket.GetUuid() == "" {
			t.Fatalf("AddTicket() did not return the generated uuid.")
		}

		// Check the ticket is persisted and loaded correctly
		r, err := tm.GetTicket(ticket.GetUuid(), user)
		if err != nil {
			t.Fatalf("tm.GetTicket() failed %s", err)
		}
		if r == nil {
			t.Fatalf("tm.GetTicket() returned no response")
		}
		if r.GetFirstName() != user.GetFirstName() {
			t.Fatalf("tm.GetTicket() did not return firstname %s. It returned %s", user.GetFirstName(), r.GetFirstName())
		}

	}

}
