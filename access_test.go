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

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	user, err := am.GetSystemSession(TestSite, "Google Sample", "Connector")
	if err != nil {
		t.Fatalf("am.GetSystemSession() failed: %v", err)
	}

	marketingUuid, err := uuid.NewRandom()
	err = am.StartWatching(marketingUuid.String(), "Marketing Task", "Unknown", user)
	if err != nil {
		t.Fatalf("am.StartWatching() failed: %v", err)
	}

	err = am.StartWatching(user.GetPersonUuid(), "Person", "Person", user)
	if err != nil {
		t.Fatalf("am.StartWatching() failed: %v", err)
	}

	items, err := am.GetWatching(user)
	if err != nil {
		t.Fatalf("am.GetWatching() failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("Expected to find two watching items, found %d", len(items))
	}

	err = am.StopWatching(user.GetPersonUuid(), "Person", user)
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

// Test access manager
func TestSystemSessionManagement(t *testing.T) {

	log := log.NewStdoutLogDebug()
	defer log.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), log)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	//user := am.GuestSession(TestSite)

	s1, err := am.GetSystemSession(TestSite, "Google Sample", "Connector")
	if err != nil {
		t.Fatalf("am.GetSystemSession() failed: %v", err)
	}
	if s1.GetFirstName() != "Google Sample" {
		t.Fatalf("am.GetSystemSession() has incorrect first name storage")
	}
	if s1.GetLastName() != "Connector" {
		t.Fatalf("am.GetSystemSession() has incorrect first name storage")
	}

	s2, err := am.GetSystemSession(TestSite, "Google Sample", "Connector")
	if err != nil {
		t.Fatalf("am.GetSystemSession() failed: %v", err)
	}
	if s1.GetPersonUuid() != s2.GetPersonUuid() {
		t.Fatalf("am.GetSystemSession() did not remember uuid of person. Namespace: " + TestSite)
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

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), log)
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
		am, _, _, _ := NewGaeAccessManager(os.Getenv("GOOGLE_CLOUD_PROJECT"), log.NewStdoutLogDebug())
		err := am.WipeDatastore(TestSite)
		if err != nil {
			fmt.Println("Failed to cleanup datastore:", err)
		}

	}

	os.Exit(code)
}
