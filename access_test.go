package security

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/zaddok/log"
)

// Test access manager
func TestWatch(t *testing.T) {

	log := log.NewStdoutLogDebug()
	defer log.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	user, err := am.GetSystemSession(TestSite, "Google Sample", "Connector")
	if err != nil {
		t.Fatalf("am.GetSystemSession() failed: %v", err)
	}

	marketingUuid, err := uuid.NewRandom()
	err = am.StartWatching(marketingUuid.String(), "Marketing Task", "Queue", user)
	if err != nil {
		t.Fatalf("am.StartWatching() failed: %v", err)
	}

	err = am.StartWatching(user.PersonUuid(), "Person", "Person", user)
	if err != nil {
		t.Fatalf("am.StartWatching() failed: %v", err)
	}

	// Check this person is recorded as watching two record
	items, err := am.GetWatching(user)
	if err != nil {
		t.Fatalf("am.GetWatching() failed: %v", err)
	}
	if len(items) != 2 {
		log.Debug("Watching")
		for _, item := range items {
			log.Debug(" - %v", item)
		}
		t.Fatalf("Expected to find two watching items, found %d", len(items))
	}

	// Check we can retrieve the list of users watching an object
	items, err = am.GetWatchers(marketingUuid.String(), user)
	if err != nil {
		t.Fatalf("am.GetWatchers() failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Expected to find one watcer for this item, found %d", len(items))
	}

	// Stop watching an item, to check the watch list goes down to 1
	err = am.StopWatching(user.PersonUuid(), "Person", user)
	if err != nil {
		t.Fatalf("am.StopWatching() failed: %v", err)
	}

	items, err = am.GetWatching(user)
	if err != nil {
		t.Fatalf("am.GetWatching() failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Expected to find one watching items, found %d", len(items))
	}

}

func TestPersonManagement(t *testing.T) {

	log := log.NewStdoutLogDebug()
	defer log.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	//user := am.GuestSession(TestSite)

	session, err := am.GetSystemSession(TestSite, "Person", "Tester")
	if err != nil {
		t.Fatalf("am.GetSystemSession() failed: %v", err)
	}
	if session == nil {
		t.Fatalf("am.GetSystemSession() failed: %v", err)
	}

	{
		p1, err := am.AddPerson(TestSite, "John", "Smythe", "John.smythe@example.com", "s1:s3", HashPassword("fish cat 190!"), "127.0.0.2", session)
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}
		if p1 == "" {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}

		person, err := am.GetPerson(p1, session)
		if err != nil {
			t.Fatalf("am.GetPerson() failed: %v", err)
		}
		if person == nil {
			t.Fatalf("am.GetPerson() failed to return record")
		}
		if person.FirstName() != "John" {
			t.Fatalf("am.AddPerson() failed to return correct first name. Returned '%s' instead of \"John\"", person.FirstName())
		}
		if person.LastName() != "Smythe" {
			t.Fatalf("am.AddPerson() failed to return correct last name")
		}
		if person.Email() != "john.smythe@example.com" {
			t.Fatalf("am.AddPerson() failed to return correct email address")
		}
		if person.LastSigninIP() != "" {
			t.Fatalf("am.AddPerson() failed to return blank last signin ip")
		}
		if len(person.Roles()) != 2 {
			t.Fatalf("am.AddPerson() failed to return two exact roles")
		}
		if !person.HasRole("s1") {
			t.Fatalf("am.AddPerson() failed to return role s1")
		}
		if !person.HasRole("s3") {
			t.Fatalf("am.AddPerson() failed to return role s3")
		}
		if person.HasRole("x") {
			t.Fatalf("am.AddPerson() should not have this role")
		}
		if person.LastSignin() != nil {
			t.Fatalf("am.AddPerson() should not not immediatly have a last sign in value")
		}
	}

	{
		user, _, err := am.Authenticate(TestSite, "john.smythe@example.com", "fish cat 190!", "127.0.0.10")
		if err != nil {
			t.Fatalf("Authenticate() failed: %v", err)
		}
		person, err := am.GetPerson(user.PersonUuid(), session)
		if err != nil {
			t.Fatalf("am.GetPerson() failed: %v", err)
		}
		if person.LastSignin() == nil {
			t.Fatalf("am.GetPerson() should return last signin time after successful authentication")
		}
		if person.LastSigninIP() != "127.0.0.10" {
			t.Fatalf("am.GetPerson() did not save last signin ip")
		}
		if person.FirstName() != "John" {
			t.Fatalf("am.GetPerson() failed to return correct first name. Returned '%s' instead of \"John\"", person.FirstName())
		}
		if person.LastName() != "Smythe" {
			t.Fatalf("am.GetPerson() failed to return correct last name")
		}
		if person.Email() != "john.smythe@example.com" {
			t.Fatalf("am.GetPerson() failed to return correct email address")
		}
		if len(person.Roles()) != 2 {
			t.Fatalf("am.GetPerson() failed to return two exact roles")
		}
	}
}

func TestSystemSessionManagement(t *testing.T) {

	log := log.NewStdoutLogDebug()
	defer log.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	//user := am.GuestSession(TestSite)

	s1, err := am.GetSystemSession(TestSite, "Google Sample", "Connector")
	if err != nil {
		t.Fatalf("am.GetSystemSession() failed: %v", err)
	}
	if s1.FirstName() != "Google Sample" {
		t.Fatalf("am.GetSystemSession() has incorrect first name storage")
	}
	if s1.LastName() != "Connector" {
		t.Fatalf("am.GetSystemSession() has incorrect first name storage")
	}

	s2, err := am.GetSystemSession(TestSite, "Google Sample", "Connector")
	if err != nil {
		t.Fatalf("am.GetSystemSession() failed: %v", err)
	}
	if s1.PersonUuid() != s2.PersonUuid() {
		t.Fatalf("am.GetSystemSession() did not remember uuid of person. Namespace: " + TestSite)
	}
}

func TestScheduledConnectors(t *testing.T) {

	tc := &ScheduledConnector{}
	tc.SetConfig("a", "b")
	if len(tc.Config) != 1 {
		t.Fatalf("SeheduledConnector.SetConfig() failed. Expect 1 items, not %d", len(tc.Config))
	}
	tc.SetConfig("1", "2")
	if len(tc.Config) != 2 {
		t.Fatalf("SeheduledConnector.SetConfig() failed. Expect 2 items, not %d", len(tc.Config))
	}
	tc.SetConfig("1", "")
	tc.SetConfig("x", "y")
	if len(tc.Config) != 2 {
		t.Fatalf("SeheduledConnector.SetConfig() failed. Expect 2 items, not %d", len(tc.Config))
	}

	l := log.NewStdoutLogDebug()
	defer l.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t), l)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}

	_, err = am.AddPerson(TestSite, "sct", "lookupsubject", "sct_tmp@example.com", "s1:s2:s3:s4:c1:c2:c3:c4:c5:c6", HashPassword("fish cat water dog 190!"), "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("AddPerson() failed: %v", err)
	}
	user, _, err := am.Authenticate(TestSite, "sct_tmp@example.com", "fish cat water dog 190!", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate() failed: %v", err)
	}

	ext1 := new(ScheduledConnector)
	ext1.Label = "moodle-fetch"
	ext1.Config = []*KeyValue{&KeyValue{"username", "james"}, &KeyValue{"password", "mypassword"}}
	err = am.AddScheduledConnector(ext1, user)
	if err != nil {
		t.Fatalf("AddScheduledConnector() failed: %s", err)
		return
	}

	ext2 := new(ScheduledConnector)
	ext2.Label = "d2l-fetch"
	ext2.Day = 4
	ext2.Hour = 9
	ext2.Frequency = "daily"
	ext2.Config = []*KeyValue{&KeyValue{"server", "test.com"}, &KeyValue{"port", "9030"}}
	err = am.AddScheduledConnector(ext2, user)
	if err != nil {
		t.Fatalf("AddScheduledConnector() failed: %s", err)
		return
	}

	search, err := am.GetScheduledConnector(ext1.Uuid, user)
	if err != nil {
		t.Fatalf("GetExternalSystem() failed unexpectedly: %v", err)
		return
	}
	if search == nil {
		t.Fatalf("GetScheduledConnector() Did not return the connector details: %s", ext1.Label)
	}

	search, err = am.GetScheduledConnector(ext2.Uuid, user)
	if err != nil {
		t.Fatalf("GetScheduledConnector() failed unexpectedly: %v", err)
		return
	}
	if search == nil {
		t.Fatalf("GetScheduledConnector() Did not return the connector details: %s", ext2.Label)
	}

	if search.Day != 4 {
		t.Fatalf("GetScheduledConnector() expected day=4. day=%d", search.Day)
	}

	if search.Uuid != ext2.Uuid {
		t.Fatalf("GetScheduledConnector() expected uuid=%s. uuid was %s", ext2.Uuid, search.Uuid)
	}

	if search.Hour != 9 {
		t.Fatalf("GetScheduledConnector() expected hour=4. hour=%d", search.Hour)
	}

	if search.Frequency != "daily" {
		t.Fatalf("GetScheduledConnector() expected frequency=daily. frequency=%s", search.Frequency)
	}

	search.Day = 3
	search.Hour = 8
	search.Frequency = "hourly"
	search.Description = "my set"
	search.SetData("c", "10")
	err = am.UpdateScheduledConnector(search, user)
	if err != nil {
		t.Fatalf("UpdateScheduledConnector() failed: %s", err)
		return
	}
	search, err = am.GetScheduledConnector(search.Uuid, user)
	if err != nil {
		t.Fatalf("GetScheduledConnector() failed: %s", err)
		return
	}
	if search.Day != 3 {
		t.Fatalf("GetScheduledConnector() expected day=3. day=%d", search.Day)
	}

	if search.Hour != 8 {
		t.Fatalf("GetScheduledConnector() expected hour=8. hour=%d", search.Hour)
	}

	if search.Description != "my set" {
		t.Fatalf("GetScheduledConnector() expected Description=\"my set\". Description was \"%s\"", search.Description)
	}

	if search.Frequency != "hourly" {
		t.Fatalf("GetScheduledConnector() expected frequency=hourly. frequency=%s", search.Frequency)
	}

	search, err = am.GetScheduledConnector(search.Uuid, user)
	if err != nil {
		t.Fatalf("GetScheduledConnector() failed unexpectedly: %v", err)
		return
	}
	if search == nil {
		t.Fatalf("GetScheduledConnector() Did not return the connector details: %s", ext2.Label)
	}
	if search.GetData("c") != "10" {
		t.Fatalf("GetScheduledConnector() Did not return updated data (c) value: %s", search.GetData("c"))
	}

	search.SetData("d", "20")
	sys, err := am.GetSystemSession(user.Site(), "Test System Session", "Account")
	err = am.UpdateScheduledConnector(search, sys)
	if err != nil {
		t.Fatalf("UpdateScheduledConnector() with system session failed unexpectedly: %v", err)
		return
	}
	search, err = am.GetScheduledConnector(search.Uuid, sys)
	if err != nil {
		t.Fatalf("GetScheduledConnector() with system session failed unexpectedly: %v", err)
		return
	}
	if len(search.Data) != 2 {
		t.Fatalf("GetScheduledConnector() should have returned two data elements, but returned: %d", len(search.Data))
		return
	}

	err = am.DeleteScheduledConnector(ext1.Uuid, user)
	if err != nil {
		t.Fatalf("DeleteScheduledConnector() failed: %s", err)
		return
	}

	search, err = am.GetScheduledConnector(ext1.Uuid, user)
	if err != nil {
		t.Fatalf("GetScheduledConnector() failed unexpectedly: %v", err)
		return
	}
	if search != nil {
		t.Fatalf("GetScheduledConnector() scheduled connector should have been deleted: %s", ext1.Label)
	}

	search, err = am.GetScheduledConnector(ext2.Uuid, user)
	if err != nil {
		t.Fatalf("GetScheduledConnector() failed unexpectedly: %v", err)
		return
	}
	if search == nil {
		t.Fatalf("GetScheduledConnector() scheduled connector should have been returned: %s", ext2.Label)
	}
}

// Test password security
func TestPasswordSecurity(t *testing.T) {
	{
		result := PasswordStrength("a1A$ri4q")
		if len(result) > 0 {
			t.Fatalf("PasswordStrength() Password should be deemed ok")
		}
	}
	{
		result := PasswordStrength("this is a long password")
		if len(result) > 0 {
			t.Fatalf("PasswordStrength() Password should be deemed ok")
		}
	}
	{
		result := PasswordStrength("this is a loong password")
		if len(result) > 0 {
			t.Fatalf("PasswordStrength() Password should be deemed ok")
		}
	}
	{
		result := PasswordStrength("this is a looong password")
		if len(result) == 0 {
			t.Fatalf("PasswordStrength() Password should not be deemed ok")
		}
	}
	{
		result := PasswordStrength("this is a long password 123")
		if len(result) == 0 {
			t.Fatalf("PasswordStrength() Password should not be deemed ok")
		}
	}
	{
		result := PasswordStrength("this is a long password abc")
		if len(result) == 0 {
			t.Fatalf("PasswordStrength() Password should not be deemed ok")
		}
	}
}

// Test access manager
func TestAccessManager(t *testing.T) {

	log := log.NewStdoutLogDebug()
	defer log.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}

	/*
		cluster := gocql.NewCluster(TEST_NODE)
		cluster.Keyspace = TEST_KEYSPACE
		cluster.ProtoVersion = 4
		cluster.Timeout = 1 * time.Minute
		cluster.Consistency = gocql.LocalOne
		cql, err := cluster.CreateSession()
		if err != nil {
			t.Fatalf("Connect to test data store failed: %v", err)
			return
		}
	*/
	host := TestSite
	first := RandomString(8)
	last := RandomString(8)
	email := first + "." + last + "@tai.io"

	am.Setting().Put(host, "self.signup", "no")

	am.Setting().Put(host, "smtp.hostname", requireEnv("SMTP_HOSTNAME", t))
	am.Setting().Put(host, "smtp.port", requireEnv("SMTP_PORT", t))
	am.Setting().Put(host, "smtp.user", requireEnv("SMTP_USER", t))
	am.Setting().Put(host, "smtp.password", requireEnv("SMTP_PASSWORD", t))
	am.Setting().Put(host, "support_team.name", requireEnv("SUPPORT_TEAM_NAME", t))
	am.Setting().Put(host, "support_team.email", requireEnv("SUPPORT_TEAM_EMAIL", t))

	// Test Signup fail
	{
		_, _, err := am.Signup(host, first, last, email, "mypassword12!", "127.0.0.1")
		if err == nil {
			t.Fatalf("am.Signup() should have failed when self.signup=no")
		}
	}

	am.Setting().Put(host, "self.signup", "yes")

	// Test Signup success
	{
		//Signup(host, email, password, first_name, last_name, ip string) (*[]string, error)
		_, token, err := am.Signup(host, first, last, email, "mypassword12!", "127.0.0.1")
		if err != nil {
			t.Fatalf("am.Signup() failed: %v", err)
		}
		if token == "" {
			t.Fatalf("am.Signup() failed: token missing")
		}

		//ActivateSignup(host, token, ip string)
		cookie, _, err := am.ActivateSignup(host, token, "127.0.0.1")
		if err != nil {
			t.Fatalf("am.ActivateSignup() failed: %v", err)
		}
		if cookie == "" {
			t.Fatalf("am.ActivateSignup() failed to return cookie")
		}

	}

	// Test Forgot Password email request
	{
		token, err := am.ForgotPasswordRequest(host, email, "127.0.0.1")
		if err != nil {
			t.Fatalf("am.ForgotPasswordRequest() failed, when it should have succeded: %v", err)
		}
		if token == "" {
			dumpSystemLog(am, host)
			t.Fatalf("am.ForgotPasswordRequest() should have returned a token")
		}

		token, err = am.ForgotPasswordRequest(host, "fake.email@example.com", "127.0.0.1")
		if err != nil {
			t.Fatalf("am.ForgotPasswordRequest() failed, when it should have succeded: %v", err)
		}
		if token != "" {
			t.Fatalf("am.ForgotPasswordRequest() should have not have returned a token")
		}

	}

}

func dumpSystemLog(am AccessManager, site string) {
	session, _ := am.GetSystemSession(site, "Test", "Test")
	items, _ := am.GetRecentSystemLog(session)
	for _, i := range items {
		fmt.Println(i)
	}
}

var TestSite string

func TestMain(m *testing.M) {
	// setup

	value := os.Getenv("SITE_HOSTNAME")
	if value == "" {
		TestSite = RandomString(10) + ".com"
	} else {
		TestSite = value
	}
	code := m.Run()

	// cleanup

	// If we used a random keyspace, we want to go ahead and
	// wipe any left behind data
	if os.Getenv("SITE_HOSTNAME") == "" && os.Getenv("GOOGLE_CLOUD_PROJECT") != "" {
		am, _, _, _ := NewGaeAccessManager(os.Getenv("GOOGLE_CLOUD_PROJECT"), "", log.NewStdoutLogDebug())
		err := am.WipeDatastore(TestSite)
		if err != nil {
			fmt.Println("Failed to cleanup datastore:", err)
		}

	}

	os.Exit(code)
}
