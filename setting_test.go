package security

import (
	"fmt"
	"testing"
)

// Test settings
func TestSettings(t *testing.T) {

	host := RandomString(20) + ".test.com"
	host2 := RandomString(20) + ".test.com"

	s, _, _ := NewGaeSetting(projectId)

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

	s, _, _ = NewGaeSetting(projectId)

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
