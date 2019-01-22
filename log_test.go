package security

import (
	"testing"

	"github.com/zaddok/log"
)

func TestEntityAudit(t *testing.T) {

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

	l := log.NewStdoutLogDebug()
	defer l.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), l)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	var session Session = nil
	var entityUuid string

	{
		_, err := am.AddPerson(TestSite, "Stacy", "Jones", "Stacy.Jones@test.com", "s1:s2:s3:s4", HashPassword("abc123--"), "127.0.0.1", nil)
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}
		session, _, err = am.Authenticate(TestSite, "stacy.jones@test.com", "abc123--", "127.0.0.1")
		if err != nil {
			t.Fatalf("am.Authenticate() failed: %v", err)
		}

		entityUuid, err = am.AddPerson(TestSite, "Matthew", "Jones", "matthew.jones@test.com", "s1:s2:s3:s4", HashPassword("abc123--"), "127.0.0.1", nil)
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}

		err = am.UpdateEntityAuditLog(entityUuid, "FirstName", "", "Matthew", "string", session)
		if err != nil {
			t.Fatalf("am.UpdateEntityAuditLog() failed: %v", err)
		}
	}

	{
		items, err := am.GetEntityAuditLog("junk", session)
		if len(items) != 0 {
			t.Fatalf("am.GetEntityAuditLog() should have returned no results, it returned %d", len(items))
		}
		items, err = am.GetEntityAuditLog(entityUuid, session)
		if len(items) != 1 {
			t.Fatalf("am.GetEntityAuditLog() should have returned one result, it returned %d", len(items))
		}

		bulk := &GaeEntityAuditLogCollection{}
		bulk.SetEntityUuidPersonUuid(entityUuid, session.GetPersonUuid(), session.GetDisplayName())
		bulk.AddItem("FirstName", "Stacy", "Jenny")
		bulk.AddItem("LastName", "Smith", "Smithe")
		bulk.AddItem("Phone", "01234", "03456")
		err = am.BulkUpdateEntityAuditLog(bulk, session)
		if err != nil {
			t.Fatalf("am.UpdateEntityAuditLog() failed: %v", err)
		}
		items, err = am.GetEntityAuditLog(entityUuid, session)
		if len(items) != 4 {
			t.Fatalf("am.GetEntityAuditLog() should have returned 5 result(s), it returned %d", len(items))
		}
	}

}
