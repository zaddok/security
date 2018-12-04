package security

import (
	"fmt"
	"testing"
)

const TEST_CASSANDRA_KEYSPACE = "realnews_test"
const TEST_CASSANDRA_NODE = "127.0.0.1"
const TEST_GAE_PROJECT_ID = "sis-test-215805"

// Test settings
func TestSettings(t *testing.T) {

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
	host := RandomString(20) + ".test.com"
	host2 := RandomString(20) + ".test.com"

	s, _, _ := NewGaeSetting(TEST_GAE_PROJECT_ID)

	// Test Put with two different hostnames
	{
		err := s.Put(host, "s1", "v1")
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
		err = s.Put(host2, "s1", "v2")
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
	}

	s, _, _ = NewGaeSetting(TEST_GAE_PROJECT_ID)

	// Test Get and ensure value for right hostname was returned
	{
		value := s.Get(host, "s1")
		if value == nil {
			t.Fatal("settings.Get() should return \"v1\" not nil.")
		}
		if *value != "v1" {
			t.Fatal(fmt.Sprintf("settings.Get() should return \"v1\" not \"%s\".", *value))
		}
	}

	{
		value := s.Get(host2, "s1")
		if value == nil {
			t.Fatal("settings.Get() should return \"v2\" not nil.")
		}
		if *value != "v2" {
			t.Fatal(fmt.Sprintf("settings.Get() should return \"v2\" not \"%s\".", *value))
		}
	}

}
