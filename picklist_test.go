package security

import (
	"fmt"
	"testing"
)

func TestPicklistStore(t *testing.T) {

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

	s, _, _ := NewGaePicklistStore(requireEnv("GAE_PROJECT_ID", t))

	// Test Put with two different hostnames
	{
		err := s.AddPicklistItem(host, "sex", "M", "Male", "Desc1")
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
		s.AddPicklistItem(host, "sex", "F", "Female", "F Desc2")

		err = s.AddPicklistItem(host2, "sex", "M", "ανηρ", "Man")
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
		s.AddPicklistItem(host2, "sex", "F", "γυνη", "Woman")

		err = s.AddPicklistItem(host2, "country", "Australia", "Australia", "Desc1")
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
		s.AddPicklistItem(host2, "country", "Greece", "Greece", "Desc1")
		s.AddPicklistItem(host2, "country", "tw", "Taiwan", "T Desc1")
	}

	s, _, _ = NewGaePicklistStore(requireEnv("GAE_PROJECT_ID", t))

	{
		pkl, err := s.GetPicklist(host, "sex")
		if err != nil {
			t.Fatalf("GetPicklist() failed: %v", err)
		}
		if pkl == nil || len(pkl) != 2 {
			t.Fatal(fmt.Sprintf("GetPicklist(\"%s\",\"sex\") contains %d items, should contain 2", host, len(pkl)))
		}
	}

	{
		item, err := s.GetPicklistItem(host, "sex", "F")
		if err != nil {
			t.Fatalf("GetPicklistItem() failed: %v", err)
		}
		if item == nil || item.GetValue() != "Female" {
			t.Fatal(fmt.Sprintf("GetPicklistItem(\"%s\",\"sex\", \"F\") should return \"Female\" not: %s", host, item.GetValue()))
		}
		if item == nil || item.GetDescription() != "F Desc2" {
			t.Fatal(fmt.Sprintf("GetPicklistItem(\"%s\",\"sex\", \"F\") should return \"Desc1\" not: %s", host, item.GetDescription()))
		}
	}

	{
		item, err := s.GetPicklistItem(host2, "country", "tw")
		if err != nil {
			t.Fatalf("GetPicklistItem() failed: %v", err)
		}
		if item == nil || item.GetValue() != "Taiwan" {
			t.Fatal(fmt.Sprintf("GetPicklistItem(\"%s\",\"country\", \"tw\") should return \"Taiwan\" not: %s", host2, item.GetValue()))
		}
		if item == nil || item.GetDescription() != "T Desc1" {
			t.Fatal(fmt.Sprintf("GetPicklistItem(\"%s\",\"country\", \"tw\") should return \"T Desc1\" not: %s", host, item.GetDescription()))
		}
	}

}
