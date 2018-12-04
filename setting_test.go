package security

import (
	"fmt"
	"testing"
	"time"

	"github.com/gocql/gocql"
)

const TEST_KEYSPACE = "realnews_test"
const TEST_NODE = "127.0.0.1"

// Test settings
func TestSettings(t *testing.T) {

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

	s := NewSetting(cql)

	{
		err := s.Put("example.com", "s1", "v1")
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
		err = s.Put("test.com", "s1", "v2")
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
	}

	s = NewSetting(cql)

	{
		value := s.Get("example.com", "s1")
		if value == nil {
			t.Fatal("settings.Get() should return \"v1\" not nil.")
		}
		if *value != "v1" {
			t.Fatal(fmt.Sprintf("settings.Get() should return \"v1\" not \"%s\".", *value))
		}
	}

	{
		value := s.Get("test.com", "s1")
		if value == nil {
			t.Fatal("settings.Get() should return \"v2\" not nil.")
		}
		if *value != "v2" {
			t.Fatal(fmt.Sprintf("settings.Get() should return \"v2\" not \"%s\".", *value))
		}
	}

}
