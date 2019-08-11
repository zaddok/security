package security

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

func TestExternalSystem(t *testing.T) {

	am, err, _, _ := NewGaeAccessManager(projectId, inferLocation(t), time.Now().Location())
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}

	_, err = am.AddPerson(TestSite, "testexternalsystem", "tmp", "testexternalsystem@example.com", "s1:s2:s3:s4:c1:c2:c3:c4:c5:c6", HashPassword("tmp"), "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("AddPerson() failed: %v", err)
	}
	user, _, err := am.Authenticate(TestSite, "testexternalsystem@example.com", "tmp", "127.0.0.1", "", "en-AU")
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
		KeyValue{"server", "http://test.com/fish"},
		KeyValue{"form", "form44"}}
	ext3, err := am.AddExternalSystem("formsite", config, user)
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

	if ext3.Describe() != "test.com" {
		t.Fatalf("GetExternalSystem() external system Describe() should return \"test.com\", not %s", ext3.Describe())
	}
}

// Fully replace contents of the destination array with the source array
func TestSyncExternalSystemId(t *testing.T) {
	src := []ExternalSystemId{
		&GaeExternalSystemId{EType: "a", EValue: "1"},
		&GaeExternalSystemId{EType: "b", EValue: "2"},
		&GaeExternalSystemId{EType: "c", EValue: "3"},
		&GaeExternalSystemId{EType: "x", EValue: ""},
	}
	dst := []ExternalSystemId{
		&GaeExternalSystemId{EType: "b", EValue: "2"},
		&GaeExternalSystemId{EType: "c", EValue: "3a"},
		&GaeExternalSystemId{EType: "d", EValue: "4"},
		&GaeExternalSystemId{EType: "y", EValue: ""},
	}

	bulk := &GaeEntityAuditLogCollection{}
	bulk.SetEntityUuidPersonUuid("student.Uuid", "updator.GetPersonUuid()", "updator.GetDisplayName()")

	SyncExternalSystemId("test", &src, &dst, bulk)

	sort.Slice(dst, func(i, j int) bool {
		return dst[i].Type() < dst[j].Type()
	})
	sort.Slice(bulk.Items, func(i, j int) bool {
		return bulk.Items[i].Attribute < bulk.Items[j].Attribute
	})

	for _, i := range dst {
		fmt.Println(i.Type(), i.Value())
	}
	for _, item := range bulk.Items {
		fmt.Println(item.Attribute, item.OldValue, "->", item.NewValue)
	}

	if len(dst) != 3 || dst[0].Type() != "a" || dst[1].Type() != "b" || dst[2].Type() != "c" {
		t.Fatalf("SyncExternalSystemId(() failed: expecting a,b,c. Found %d items", len(dst))
	}

	if bulk.Items[0].Attribute != "test.a" || bulk.Items[1].Attribute != "test.c" || bulk.Items[2].Attribute != "test.d" {
		t.Fatalf("SyncExternalSystemId(() failed: expecting test.a,test.c,test.d")
	}

}
