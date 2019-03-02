package security

import (
	"fmt"
	"testing"

	"github.com/zaddok/log"
)

func TestExternalSystem(t *testing.T) {

	l := log.NewStdoutLog()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), l)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}

	_, err = am.AddPerson(TestSite, "testexternalsystem", "tmp", "testexternalsystem@example.com", "s1:s2:s3:s4:c1:c2:c3:c4:c5:c6", HashPassword("tmp"), "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("AddPerson() failed: %v", err)
	}
	user, _, err := am.Authenticate(TestSite, "testexternalsystem@example.com", "tmp", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate() failed: %v", err)
	}

	config := []KeyValue{
		KeyValue{"username", "james"},
		KeyValue{"password", "mypassword"}}
	ext1, err := am.AddExternalSystem("moodle", config, user)
	if err != nil {
		t.Fatalf("AddExternalSystem() failed: %s", err)
		return
	}
	if ext1.Uuid() == "" {
		t.Fatalf("GetExternalSystem() Did not return the external system uuid: %s", ext1.Uuid())
	}

	config = []KeyValue{
		KeyValue{"server", "test.com"},
		KeyValue{"port", "9030"}}
	ext2, err := am.AddExternalSystem("moodle", config, user)
	if err != nil {
		t.Fatalf("AddExternalSystem() failed: %s", err)
		return
	}

	config = []KeyValue{
		KeyValue{"server", "test.com"},
		KeyValue{"form", "form44"}}
	_, err = am.AddExternalSystem("formsite", config, user)
	if err != nil {
		t.Fatalf("AddExternalSystem() failed: %s", err)
		return
	}

	{
		search, err := am.GetExternalSystem(ext1.Uuid(), user)
		if err != nil {
			t.Fatalf("GetExternalSystem() failed unexpectedly: %v", err)
			return
		}
		if search == nil {
			t.Fatalf("GetExternalSystem() Did not return the external system: %s", ext1.Type())
		}
		if len(search.Config()) != 2 {
			t.Fatalf("GetExternalSystem(%s) Did not return the external system config items correctly. Expect 2 items, not %d", ext1.Uuid(), len(search.Config()))
		}
		if search.Type() != "moodle" {
			fmt.Println(search)
			t.Fatalf("GetExternalSystem() Did not return the external system type 'moodle'. Found '%s'", search.Type())
		}
	}

	{
		search, err := am.GetExternalSystem(ext2.Uuid(), user)
		if err != nil {
			t.Fatalf("GetExternalSystem() failed unexpectedly: %v", err)
			return
		}
		if search == nil {
			t.Fatalf("GetExternalSystem() Did not return the external system: %s", ext2.Type())
		}
	}

	{
		search, err := am.GetExternalSystems(user)
		if err != nil {
			t.Fatalf("GetExternalSystem() failed unexpectedly: %v", err)
			return
		}
		if search == nil {
			t.Fatalf("GetExternalSystem() Did not return the external system search result variable")
		}
		if len(search) != 3 {
			t.Fatalf("GetExternalSystems() should return 3 results, not %v", len(search))
		}
	}

	{
		search, err := am.GetExternalSystemsByType("moodle", user)
		if err != nil {
			t.Fatalf("GetExternalSystemByType() failed unexpectedly: %v", err)
			return
		}
		if search == nil {
			t.Fatalf("GetExternalSystemByType() Did not return the external system search result variable")
		}
		if len(search) != 2 {
			t.Fatalf("GetExternalSystemsByType() should return 2 results, not %v", len(search))
		}
	}

	err = am.DeleteExternalSystem(ext1.Uuid(), user)
	if err != nil {
		t.Fatalf("DeleteExternalSystem() failed: %s", err)
		return
	}

	search, err := am.GetExternalSystem(ext1.Uuid(), user)
	if err != nil {
		t.Fatalf("GetExternalSystem() failed unexpectedly: %v", err)
		return
	}
	if search != nil {
		t.Fatalf("GetExternalSystem() external system should have been deleted: %s", ext1.Type())
	}

	search, err = am.GetExternalSystem(ext2.Uuid(), user)
	if err != nil {
		t.Fatalf("GetExternalSystem() failed unexpectedly: %v", err)
		return
	}
	if search == nil {
		t.Fatalf("GetExternalSystem() external system should still exist: %s", ext2.Type())
	}
}
