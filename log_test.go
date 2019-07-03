package security

import (
	"testing"
	"time"

	"github.com/zaddok/log"
)

func TestEntityAuditLogCollection(t *testing.T) {
	bulk := &GaeEntityAuditLogCollection{}
	bulk.SetEntityUuidPersonUuid("uuid", "uuid", "name")

	bulk.AddDocumentItem("Support", "passport", "", "file.txt")
	bulk.AddDocumentItem("Support", "passport", "file.txt", "")

	items := bulk.GetItems()
	if len(items) != 2 {
		t.Fatalf("AddDocumentItem() calls should have resulted in two items: %d", len(items))
	}

	if items[0].GetActionType() != "add" {
		t.Fatalf("AddDocumentItem() item 0 should be add")
	}
	if items[0].GetDocumentFilename() != "file.txt" {
		t.Fatalf("AddDocumentItem() item 0 filename should be 'file.txt'")
	}

	if items[1].GetActionType() != "delete" {
		t.Fatalf("AddDocumentItem() item 0 should be add")
	}
	if items[1].GetDocumentFilename() != "file.txt" {
		t.Fatalf("AddDocumentItem() item 1 filename should should be 'file.txt'")
	}
	if items[1].GetDocumentType() != "passport" {
		t.Fatalf("AddDocumentItem() item 1 document type should should be 'passport'")
	}

}

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

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t), time.Now().Location())
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	var session Session = nil
	var personUuid string

	{
		_, err := am.AddPerson(TestSite, "Stacy", "Jones", "Stacy.Jones@test.com", "s1:s2:s3:s4", HashPassword("abc123--"), "127.0.0.1", nil)
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}
		session, _, err = am.Authenticate(TestSite, "stacy.jones@test.com", "abc123--", "127.0.0.1", "", "en-AU")
		if err != nil {
			t.Fatalf("am.Authenticate() failed: %v", err)
		}

		personUuid, err = am.AddPerson(TestSite, "Matthew", "Jones", "matthew.jones@test.com", "s1:s2:s3:s4", HashPassword("Tbc923--"), "127.0.0.1", nil)
		if err != nil {
			t.Fatalf("am.AddPerson() failed: %v", err)
		}

		/*
			err = am.UpdateEntityAuditLog(personUuid, "FirstName", "", "Matthew", "string", session)
			if err != nil {
				t.Fatalf("am.UpdateEntityAuditLog() failed: %v", err)
			}
		*/
	}

	{
		items, err := am.GetEntityChangeLog("junk", session)
		if err != nil {
			t.Fatalf("am.GetEntityChangeLog() failed %s", err)
		}
		if len(items) != 0 {
			t.Fatalf("am.GetEntityChangeLog() should have returned no results, it returned %d", len(items))
		}

		// One log entry was created when the person was added
		items, err = am.GetEntityChangeLog(personUuid, session)
		if err != nil {
			t.Fatalf("am.GetEntityChangeLog() failed %s", err)
		}
		if len(items) != 1 {
			t.Fatalf("am.GetEntityChangeLog() should have returned one result, it returned %d", len(items))
		}

		err = am.UpdatePerson(personUuid, "Matt", "Jones", "matt.jones@test.com", "s1:s2:s3:s4", "", session)
		items, err = am.GetEntityChangeLog(personUuid, session)
		if len(items) != 2 { // once for the add, second for the update
			t.Fatalf("am.GetEntityAuditLog() should have returned 2 result(s), it returned %d", len(items))
		}
	}

}
