package security

type Throttle interface {
	Check(key string) (bool, error)
	Increment(key string) error
	Clear(key string) error
}
