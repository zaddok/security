package security

import (
	"testing"

	"github.com/zaddok/log"
)

// Test access manager
func TestAccessManager(t *testing.T) {

	log := log.NewStdoutLogDebug()
	defer log.Close()

	am, err := NewGaeAccessManager(requireEnv("GAE_PROJECT_ID", t), log)
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
	host := RandomString(8) + ".com"
	first := RandomString(8)
	last := RandomString(8)
	email := first + "." + last + "@.test.com"

	am.Setting().Put(host, "self.signup", "no")

	// Test Signup fail
	{
		//Signup(host, email, password, first_name, last_name, ip string) (*[]string, error)
		_, _, err := am.Signup(host, email, "mypassword123", first, last, "127.0.0.1")
		if err == nil {
			t.Fatalf("am.Signup() should have failed when self.signup=no")
		}
	}

	am.Setting().Put(host, "self.signup", "yes")

	// Test Signup success
	{
		//Signup(host, email, password, first_name, last_name, ip string) (*[]string, error)
		_, token, err := am.Signup(host, email, "mypassword123", first, last, "127.0.0.1")
		if err != nil {
			t.Fatalf("am.Signup() failed: %v", err)
		}
		if token == "" {
			t.Fatalf("am.Signup() failed: token missing")
		}
	}

}
