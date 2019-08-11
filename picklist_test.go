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

	_, client, ctx := NewGaeSetting(projectId)
	s := NewGaePicklistStore(projectId, client, ctx)

	// Test Put with two different hostnames
	{
		err := s.AddPicklistItem(host, "sex", "M", "Male", "Desc1", 1)
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
		s.AddPicklistItem(host, "sex", "F", "Female", "F Desc2", 2)

		err = s.AddPicklistItem(host2, "sex", "M", "ανηρ", "Man", 3)
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
		s.AddPicklistItem(host2, "sex", "F", "γυνη", "Woman", 4)

		err = s.AddPicklistItem(host2, "country", "Australia", "Australia", "Desc1", 1)
		if err != nil {
			t.Fatalf("settings.Put() failed: %v", err)
		}
		s.AddPicklistItem(host2, "country", "Greece", "Greece", "Desc1", 10)
		s.AddPicklistItem(host2, "country", "tw", "Taiwan", "T Desc1", 10)
	}

	s = NewGaePicklistStore(projectId, client, ctx)

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
		err := s.AddPicklistItem(host, "sex", "U", "Unspecified", "Description of Unspecified", 0)
		pkl, err := s.GetPicklistOrdered(host, "sex") // F, M, U
		if err != nil {
			t.Fatalf("GetPicklist() failed: %v", err)
		}
		if pkl == nil || len(pkl) != 3 {
			t.Fatal(fmt.Sprintf("GetPicklist(\"%s\",\"sex\") contains %d items, should contain 2", host, len(pkl)))
		}
		if pkl[0].GetKey() != "u" {
			t.Fatal(fmt.Sprintf("GetPicklistOrdered(\"%s\",\"sex\") expected \"u\" first, but got %s", host, pkl[0].GetKey()))
		}
		if pkl[1].GetValue() != "Male" {
			t.Fatal(fmt.Sprintf("GetPicklistOrdered(\"%s\",\"sex\") expected \"Male\" second, but got %s", host, pkl[1].GetValue()))
		}
		if pkl[2].GetKey() != "f" {
			t.Fatal(fmt.Sprintf("GetPicklistOrdered(\"%s\",\"sex\") expected \"f\" third, but got %s", host, pkl[2].GetKey()))
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
		if item == nil || item.GetIndex() != 2 {
			t.Fatal(fmt.Sprintf("GetPicklistItem(\"%s\",\"sex\", \"F\") should return index \"2\" not: %d", host, item.GetIndex()))
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
