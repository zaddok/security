package security

import (
	"fmt"
	"testing"

	"github.com/zaddok/log"
)

// Test access account manager
func TestAccountManagement(t *testing.T) {

	log := log.NewStdoutLogDebug()
	defer log.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GAE_PROJECT_ID", t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	user := am.GuestSession(TestSite)

	// Test Create account
	{
		_, err := am.AddPerson(TestSite, "Stacy", "Smith", "Stacy@test.com", HashPassword("abc123--"), "127.0.0.1")
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}
		people, err := am.GetPeople(user)
		if err != nil {
			t.Fatalf("am.GetPeople() failed: %v", err)
		}
		if len(people) != 1 {
			t.Fatalf("am.GetPeople() should return one result, not %d", len(people))
		}
		if people[0].GetFirstName() != "Stacy" {
			t.Fatalf("am.GetPeople() did not return correct first name. Expected \"Stacy\", found %s", people[0].GetFirstName())
		}
		if people[0].GetLastName() != "Smith" {
			t.Fatalf("am.GetPeople() did not return correct last name. Expected \"Smith\", found %s", people[0].GetLastName())
		}
		if people[0].GetSite() != TestSite {
			t.Fatalf("am.GetPeople() did not return correct site. Expected \"%s\", found %s", TestSite, people[0].GetSite())
		}
		if people[0].GetEmail() != "stacy@test.com" {
			t.Fatalf("am.GetPeople() did not return correct email. Expected \"stacy@test.com\", found %s", people[0].GetEmail())
		}
	}

	// Test Create Anoter account
	var uuid string
	{
		uuid, err = am.AddPerson(TestSite, "Jason", "Smith", "jason@test.com", HashPassword("abc123--"), "127.0.0.1")
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}
		people, err := am.GetPeople(user)
		if err != nil {
			t.Fatalf("am.GetPeople() failed: %v", err)
		}
		if len(people) != 2 {
			t.Fatalf("am.GetPeople() should return two results, not %d", len(people))
		}
	}

	// Test updating an account
	{
		session, _, err := am.Authenticate(TestSite, "stacy@test.com", "abc123--", "127.0.0.1")
		if err != nil {
			t.Fatalf("am.Session() failed: %v", err)
		}
		//session, err := am.Session(TestSite, cookie)
		//if err != nil {
		//	t.Fatalf("am.Session() failed: %v", err)
		//}
		person, err := am.GetPerson(uuid, session)
		if err != nil {
			t.Fatalf("am.GetPerson() failed: %v", err)
		}

		err = am.UpdatePerson(uuid, "Jason2", "Smith2", person.GetEmail(), "", session)
		if err != nil {
			t.Fatalf("am.UpdatePerson() failed: %v", err)
		}
		//if len(people) != 2 {
		//	t.Fatalf("am.GetPeople() should return two results, not %d", len(people))
		//}

		entries, err := am.GetRecentSystemLog(session)
		if err != nil {
			t.Fatalf("am.GetRecentSystemLog() failed: %v", err)
		}
		for _, e := range entries {
			fmt.Println(e)
		}

	}

}
