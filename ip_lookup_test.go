package security

import (
	"testing"
	"time"

	"github.com/zaddok/log"
)

func TestIPLookup(t *testing.T) {

	l := log.NewStdoutLogDebug()
	defer l.Close()

	// Initialize helper API objects
	am, err, _, _ := NewGaeAccessManager(projectId, inferLocation(t), time.Now().Location())
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}

	// Setup accounts for peopel to participate in the test workflow
	_, err = am.AddPerson(TestSite, "ip", "tmp", "ip.tmp1@example.com", "s1:s2:s3:s4:c1:c2:c3:c4:c5:c6", HashPassword("tmpA@9040hi"), "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("AddPerson() failed: %v", err)
	}
	/*
		session, _, err := am.Authenticate(TestSite, "ip.tmp1@example.com", "ip@9040hi", "127.0.0.1", "", "en-AU")
		if err != nil {
			t.Fatalf("Authenticate() failed: %v", err)
		}
	*/

	{
		gs := am.GuestSession("example.com", "111.243.45.179", "", "en-US")
		message := make(map[string]interface{})
		message["type"] = "ip-lookup"
		message["ip"] = gs.IP()
		err := ipLookupTask(am)(gs, message)
		if err != nil {
			t.Fatalf("ipLookup() task failed: %v", err)
		}

		ip, err := am.LookupIp(gs.IP())
		if err != nil {
			t.Fatalf("LookupIp() failed: %v", err)
		}
		if ip == nil {
			t.Fatalf("ipLookup() lookup %s task failed. No IP response value returned", gs.IP())
		}
		if ip.Country() != "Taiwan" {
			t.Fatalf("LookupIp() expected country \"Taiwan\" but found %s", ip.Country())
		}
		if ip.Region() != "Taipei City" {
			t.Fatalf("LookupIp() expected region \"Taipei City\" but found %s", ip.Region())
		}
	}

	{
		gs := am.GuestSession("example.com", "128.250.18.1", "", "en-US")
		message := make(map[string]interface{})
		message["type"] = "ip-lookup"
		message["ip"] = gs.IP()
		err := ipLookupTask(am)(gs, message)
		if err != nil {
			t.Fatalf("ipLookup() task failed: %v", err)
		}

		ip, err := am.LookupIp(gs.IP())
		if err != nil {
			t.Fatalf("LookupIp() failed: %v", err)
		}
		if ip.Country() != "Australia" {
			t.Fatalf("LookupIp() expected country \"Australia\" but found %s", ip.Country())
		}
		if ip.Region() != "Victoria" {
			t.Fatalf("LookupIp() expected region \"Victoria\" but found %s", ip.Region())
		}
		if ip.Organisation() != "The University of Melbourne, Melbourne, Victoria" {
			t.Fatalf("LookupIp() expected organisation \"The University of Melbourne, Melbourne, Victoria\" but found %s", ip.Organisation())
		}
	}

}
