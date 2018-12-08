package security

import (
	"fmt"
	"os"
	"testing"
)

func requireEnv(name string, t *testing.T) string {
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("Environment variable required: %s", name)
	}
	return value
}

// Test settings
func TestSettings(t *testing.T) {

	/*
		cluster := gocql.NewCluster(requireEnv("CASSANDRA_NODE", t))
		cluster.Keyspace = requireEnv("CASSANDRA_KEYSPACE", t)
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

	s, _, _ := NewGaeSetting(requireEnv("GAE_PROJECT_ID", t))

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

	s, _, _ = NewGaeSetting(requireEnv("GAE_PROJECT_ID", t))

	// Test Get and ensure value for right hostname was returned
	{
		value := s.Get(host, "s1")
		if value == nil {
			t.Fatal(fmt.Sprintf("settings.Get(\"%s\",\"s1\") should return \"v1\" not nil.", host))
		}
		if *value != "v1" {
			t.Fatal(fmt.Sprintf("settings.Get(\"%s\",\"s1\") should return \"v1\" not \"%s\".", host, *value))
		}
	}

	{
		value := s.Get(host2, "s1")
		if value == nil {
			t.Fatal(fmt.Sprintf("settings.Get(\"%s\",\"s1\") should return \"v2\" not nil.", host2))
		}
		if *value != "v2" {
			t.Fatal(fmt.Sprintf("settings.Get(\"%s\",\"s1\") should return \"v2\" not \"%s\".", host2, *value))
		}
	}

}
