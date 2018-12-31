package security

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
)

type GaeThrottle struct {
	client   *datastore.Client
	ctx      context.Context
	settings Setting

	Window   int64
	Lockout  int64
	Attempts int64
}

type GaeThrottleItem struct {
	Attempts int64
	Updated  int64
}

func NewGaeThrottle(settings Setting, client *datastore.Client, ctx context.Context) Throttle {
	t := &GaeThrottle{
		client:   client,
		ctx:      ctx,
		settings: settings,
		Window:   60,
		Lockout:  60,
		Attempts: 3, // Default to three attempts per minute, lock for one minute.
	}
	return t
}

func (t *GaeThrottle) IsThrottled(key string) (bool, error) {
	var item GaeThrottleItem

	k := datastore.NameKey("Throttle", key, nil)
	err := t.client.Get(t.ctx, k, &item)

	if err == datastore.ErrNoSuchEntity {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if item.Attempts <= t.Attempts {
		return false, nil
	}
	// Max attempts hit

	now := time.Now().Unix()

	if item.Updated+t.Lockout > now {
		// We are within the lockout period
		return true, nil
	}

	return false, nil
}

// Flag that a countable throttle event has occurred. For example: Signin failure,
// password reset request. Note that two concurrent calls to Increment may result
// in only one countable event being registered.
func (t *GaeThrottle) Increment(key string) error {
	var item GaeThrottleItem
	k := datastore.NameKey("Throttle", key, nil)
	err := t.client.Get(t.ctx, k, &item)

	now := time.Now().Unix()
	item.Updated = now

	if err != nil && err != datastore.ErrNoSuchEntity {
		return err
	}
	if err == datastore.ErrNoSuchEntity {
		item.Attempts = 1
	} else {
		if item.Updated < now-t.Window {
			// Last hit is dated longer than the window period, reset counter
			item.Attempts = 1
		} else {
			// Last hit is dated within the window period, increment counter
			item.Attempts = item.Attempts + 1
		}
	}

	if _, err := t.client.Put(t.ctx, k, &item); err != nil {
		return err
	}

	return nil
}

func (t *GaeThrottle) Clear(key string) error {
	k := datastore.NameKey("Throttle", key, nil)
	return t.client.Delete(t.ctx, k)
}
