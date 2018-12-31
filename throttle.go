package security

type Throttle interface {
	IsThrottled(key string) (bool, error)
	Increment(key string) error
	Clear(key string) error
}
