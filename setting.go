package security

const CACHE_TIMEOUT = 60

type Setting interface {
	Get(site, name string) *string
	GetWithDefault(site, name, defaultValue string) string
	GetInt(site, name string, defaultValue int) int
	GetList(site, name string) []string
	Put(site, name, value string) error
	List(site string) map[string]string
}
