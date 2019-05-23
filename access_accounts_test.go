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

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	var user Session = am.GuestSession(TestSite)

	// Test Create account
	{

		// Create account
		_, err := am.AddPerson(TestSite, "Stacy", "Smith", "TACM.Stacy@test.com", "s1:s2:s3:s4", HashPassword("fIr10g-!"), "127.0.0.1", nil)
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}

		// Get people should fail with guest session
		people, err := am.GetPeople(user)
		if err == nil && err.Error() != "Permission denied" {
			t.Fatalf("am.GetPeople() should fail with permission denied. %v", err)
		}

		// Authenticate to get a session object
		msg := ""
		user, msg, err = am.Authenticate(TestSite, "tacm.stacy@test.com", "fIr10g-!", "127.0.0.1")
		if err != nil {
			t.Fatalf("am.Authenticate() failed: %v", err)
		}
		if !user.IsAuthenticated() {
			t.Fatalf("am.Authenticate() user session should have been considered authenticated: " + msg)
		}
		if !user.HasRole("s1") {
			t.Fatalf("am.Authenticate() user role 's1' missing")
		}
		if !user.HasRole("s4") {
			t.Fatalf("am.Authenticate() user role 's1' missing")
		}
		if user.HasRole("s100") {
			t.Fatalf("am.Authenticate() user role 's100' not expected")
		}

		// Refetch the session object (it would have been cached)
		user2, err := am.Session(TestSite, user.GetToken())
		if err != nil {
			t.Fatalf("am.Session() failed: %v", err)
		}
		if user2 == nil {
			t.Fatalf("am.Session() failed to return cached sesion object")
		}
		if !user2.IsAuthenticated() {
			t.Fatalf("am.Authenticate() user session should have been considered authenticated: " + user.GetToken())
		}
		if !user2.HasRole("s1") {
			t.Fatalf("am.Authenticate() user role 's1' missing")
		}
		if !user2.HasRole("s4") {
			t.Fatalf("am.Authenticate() user role 's1' missing")
		}
		if user2.HasRole("s100") {
			t.Fatalf("am.Authenticate() user role 's100' not expected")
		}

		// Get people should now succeed
		people, err = am.GetPeople(user)
		if err != nil {
			t.Fatalf("am.GetPeople() failed: %v", err)
		}

		if len(people) != 1 {
			t.Fatalf("am.GetPeople() should return one result, not %d", len(people))
		}
		if people[0].FirstName() != "Stacy" {
			t.Fatalf("am.GetPeople() did not return correct first name. Expected \"Stacy\", found %s", people[0].FirstName())
		}
		if people[0].LastName() != "Smith" {
			t.Fatalf("am.GetPeople() did not return correct last name. Expected \"Smith\", found %s", people[0].LastName())
		}
		if people[0].Site() != TestSite {
			t.Fatalf("am.GetPeople() did not return correct site. Expected \"%s\", found %s", TestSite, people[0].Site())
		}
		if people[0].Email() != "tacm.stacy@test.com" {
			t.Fatalf("am.GetPeople() did not return correct email. Expected \"stacy@test.com\", found %s", people[0].Email())
		}
	}

	// Test Create Anoter account
	var uuid string
	{
		uuid, err = am.AddPerson(TestSite, "Jason", "Smith", "jason@test.com", "s1:s2:s3:s4", HashPassword("fIr10g--"), "127.0.0.1", nil)
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
		session, _, err := am.Authenticate(TestSite, "tacm.stacy@test.com", "fIr10g-!", "127.0.0.1")
		if err != nil {
			t.Fatalf("am.Session() failed: %v", err)
		}

		err = am.UpdatePerson(uuid, "Jason2", "Smith2", "tacm.stacy@test.com2", "s1:s2:s4", "pea fish 1! apple", session)
		if err != nil {
			t.Fatalf("am.UpdatePerson() failed: %v", err)
		}

		person2, err := am.GetPerson(uuid, session)
		if err != nil {
			t.Fatalf("am.GetPerson() failed: %v", err)
		}
		if person2.FirstName() != "Jason2" {
			t.Fatalf("am.UpdatePerson/GetPerson() first name update failed")
		}
		if person2.LastName() != "Smith2" {
			t.Fatalf("am.UpdatePerson/GetPerson() first name update failed")
		}
		if person2.Email() != "tacm.stacy@test.com2" {
			t.Fatalf("am.UpdatePerson/GetPerson() first name update failed")
		}
		if len(person2.Roles()) != 3 {
			t.Fatalf("am.UpdatePerson/GetPerson() role update failed. expect three roles, not %d", len(person2.Roles()))
		}
		if person2.Roles()[0] != "s1" {
			t.Fatalf("am.UpdatePerson/GetPerson() role update failed: expect role 1 is \"s1\" not %s", person2.Roles()[0])
		}
		if person2.Roles()[1] != "s2" {
			t.Fatalf("am.UpdatePerson/GetPerson() role update failed: expect role 2 is \"s2\" not %s", person2.Roles()[1])
		}
		if person2.Roles()[2] != "s4" {
			t.Fatalf("am.UpdatePerson/GetPerson() role update failed: expect role 3 is \"s4\" not %s", person2.Roles()[2])
		}

		entries, err := am.GetRecentSystemLog(session)
		if err != nil {
			t.Fatalf("am.GetRecentSystemLog() failed: %v", err)
		}
		for _, e := range entries {
			fmt.Println(e)
		}

	}

}

// Test access account manager
func TestAccountCheckEmail(t *testing.T) {

	log := log.NewStdoutLogDebug()
	defer log.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}

	{
		exists, err := am.CheckEmailExists(TestSite, "Check0092.Stacy@test.com")
		if err != nil {
			t.Fatalf("am.CheckEmailExists() Failed: %v", err)
		}
		if exists {
			t.Fatalf("am.CheckEmailExists() Failed: Email should not exist!")
		}
	}

	{
		_, err := am.AddPerson(TestSite, "Check", "Smith", "Check0092.Stacy@test.com", "s1:s2:s3:s4", HashPassword("fIr10g-!"), "127.0.0.1", nil)
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}

		exists, err := am.CheckEmailExists(TestSite, "Check0092.Stacy@test.com")
		if err != nil {
			t.Fatalf("am.CheckEmailExists() Failed: %v", err)
		}
		if !exists {
			t.Fatalf("am.CheckEmailExists() Failed: Email should exist!")
		}
	}
}
