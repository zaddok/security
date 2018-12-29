package security

import (
	"context"
	"errors"

	"cloud.google.com/go/datastore"
)

type GaeThrottle struct {
	client   *datastore.Client
	ctx      context.Context
	settings Setting
}

type GaeThrottleItem struct {
	Key      string
	Attempts int64
	Updated  int64
}

func NewThrottle(settings Setting, client *datastore.Client, ctx context.Context) Throttle {
	t := &GaeThrottle{
		client:   client,
		ctx:      ctx,
		settings: settings,
	}
	return t
}

func (t *GaeThrottle) Check(key string) (bool, error) {
	return false, errors.New("Unimeplmented")
}

func (t *GaeThrottle) Increment(key string) error {
	return errors.New("Unimeplmented")
}

func (t *GaeThrottle) Clear(key string) error {
	return errors.New("Unimeplmented")
}
