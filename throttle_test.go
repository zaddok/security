package security

import (
	"testing"
)

func TestThrottle(t *testing.T) {

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

	s, client, ctx := NewGaeSetting(requireEnv("GOOGLE_CLOUD_PROJECT", t))
	throttle := NewGaeThrottle(s, client, ctx)

	// Test basic operation
	{
		email := RandomString(10) + "@example.com"

		// Check this random email address is not throttled
		v, err := throttle.IsThrottled(email)
		if err != nil {
			t.Fatalf("throttle.IsThrottled() failed: %v", err)
		}
		if v {
			t.Fatalf("throttle.IsThrottled() should not be throttled")
		}

		// Should still not be throttled
		err = throttle.Increment(email)
		if err != nil {
			t.Fatalf("throttle.Increment() failed: %v", err)
		}
		v, err = throttle.IsThrottled(email)
		if err != nil {
			t.Fatalf("throttle.IsThrottled() failed: %v", err)
		}
		if v {
			t.Fatalf("throttle.IsThrottled() should not be throttled")
		}

		// Should still not be throttled
		err = throttle.Increment(email)
		if err != nil {
			t.Fatalf("throttle.Increment() failed: %v", err)
		}
		v, err = throttle.IsThrottled(email)
		if err != nil {
			t.Fatalf("throttle.IsThrottled() failed: %v", err)
		}
		if v {
			t.Fatalf("throttle.IsThrottled() should not be throttled")
		}

		// Should still not be throttled
		err = throttle.Increment(email)
		if err != nil {
			t.Fatalf("throttle.Increment() failed: %v", err)
		}
		v, err = throttle.IsThrottled(email)
		if err != nil {
			t.Fatalf("throttle.IsThrottled() failed: %v", err)
		}
		if v {
			t.Fatalf("throttle.IsThrottled() should not be throttled")
		}

		// Should be throttled
		err = throttle.Increment(email)
		if err != nil {
			t.Fatalf("throttle.Increment() failed: %v", err)
		}
		v, err = throttle.IsThrottled(email)
		if err != nil {
			t.Fatalf("throttle.IsThrottled() failed: %v", err)
		}
		if !v {
			t.Fatalf("throttle.IsThrottled() should be throttled")
		}

	}

}
