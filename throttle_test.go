package security

import (
	"testing"
)

func TestThrottle(t *testing.T) {

	s, client, ctx := NewGaeSetting(projectId)
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
