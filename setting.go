package security

const CACHE_TIMEOUT = 60

type Setting interface {
	Get(site, name string) *string
	GetWithDefault(site, name, defaultValue string) string
	GetInt(site, name string, defaultValue int) int
	Put(site, name, value string) error
	List(site string) map[string]map[string]string
}
