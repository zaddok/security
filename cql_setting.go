package security

import (
	"strconv"
	"strings"
	"time"

	"github.com/gocql/gocql"
)

type CqlSetting struct {
	cql     *gocql.Session
	expires time.Time
	sites   map[string]map[string]string
}

func NewCqlSetting(cql *gocql.Session) Setting {
	s := &CqlSetting{
		cql: cql,
	}
	return s
}

// Lookup a configuration setting. Loads from database only if cache has expired.
func (s *CqlSetting) Get(site, name string) *string {
	s.refreshCache()

	sm, exists := s.sites[site]
	if !exists {
		return nil
	}

	value, exists := sm[strings.ToLower(name)]

	if exists {
		return &value
	}

	return nil
}

// Lookup a configuration setting. Loads from database only if cache has expired.
func (s *CqlSetting) GetWithDefault(site, name string, defaultValue string) string {
	s.refreshCache()

	sm, exists := s.sites[site]
	if !exists {
		return defaultValue
	}

	value, exists := sm[strings.ToLower(name)]

	if exists {
		return value
	}

	return defaultValue
}

// Lookup a configuration setting. Loads from database only if cache has expired.
func (s *CqlSetting) GetInt(site, name string, defaultValue int) int {
	s.refreshCache()

	sm, exists := s.sites[site]
	if !exists {
		return defaultValue
	}

	value, exists := sm[strings.ToLower(name)]

	if exists {
		i, err := strconv.Atoi(value)
		if err != nil {
			panic(err)
		}
		return i
	}

	return defaultValue
}

// Store a configuration setting. Stores in cache, and flushes through to database.
func (s *CqlSetting) Put(site, name, value string) error {
	name = strings.ToLower(name)

	err := s.cql.Query("update setting set value=? where site=? and name=?", value, site, name).Exec()
	if err != nil {
		return err
	}

	if s.sites == nil {
		s.sites = make(map[string]map[string]string)
	}

	sm, exists := s.sites[site]
	if !exists {
		sm = make(map[string]string)
		s.sites[site] = sm
	}

	s.sites[site][name] = value
	return nil
}

// Return all configuration settings. Loads from database only if cache has expired.
func (s *CqlSetting) List(site string) map[string]string {
	all := make(map[string]string)

	s.refreshCache()

	if _, exists := s.sites[site]; !exists {
		return all
	}

	// Return a copy of the settings map so it can't be altered
	// by the receiving function
	for k, v := range s.sites[site] {
		all[k] = v
	}

	return all
}

// Reload settings from cache if cache has expired
func (s *CqlSetting) refreshCache() {
	if s.sites == nil || s.expires.Before(time.Now()) {
		s.sites = s.load()
		s.expires = time.Now().Add(time.Duration(CACHE_TIMEOUT) * time.Second)
	}
}

// Lookup all settings from the database
func (s *CqlSetting) load() map[string]map[string]string {
	all := make(map[string]map[string]string)

	rows := s.cql.Query("select site, name, value from setting").Iter()

	var site string
	var name string
	var value string
	for rows.Scan(&site, &name, &value) {
		_, exists := all[site]
		if !exists {
			all[site] = make(map[string]string)
		}
		all[site][name] = value
	}

	err := rows.Close()
	if err != nil {
		panic(err)
	}

	return all
}
