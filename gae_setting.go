package security

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
)

type GaeSetting struct {
	client  *datastore.Client
	ctx     context.Context
	expires time.Time
	sites   map[string]map[string]string
}

func NewGaeSetting(projectID string) (Setting, *datastore.Client, context.Context) {
	ctx := context.Background()

	client, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		fmt.Printf("Failed to create client: %v", err)
	}

	s := &GaeSetting{
		client: client,
		ctx:    ctx,
	}
	return s, client, ctx
}

// Lookup a configuration setting. Loads from database only if cache has expired.
func (s *GaeSetting) Get(site, name string) *string {
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

func (s *GaeSetting) GetList(site string, key string) []string {
	content := s.Get(site, key)
	var fields []string
	if content != nil && strings.TrimSpace(*content) != "" {
		fields = strings.Split(strings.TrimSpace(*content), ";")
	}
	//TODO: trim space?
	return fields[:]
}

// Lookup a configuration setting. Loads from database only if cache has expired.
func (s *GaeSetting) GetWithDefault(site, name string, defaultValue string) string {
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
func (s *GaeSetting) GetInt(site, name string, defaultValue int) int {
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
func (s *GaeSetting) Put(site, name, value string) error {
	//TODO: Delete settings where value == ""
	name = strings.ToLower(name)

	oldValue := s.Get(site, name)
	if oldValue != nil && *oldValue == value {
		return nil
	}

	type SI struct {
		Site  string
		Name  string
		Value string
	}
	k := datastore.NameKey("Setting", site+"|"+name, nil)
	i := SI{Site: site, Name: name, Value: value}
	if _, err := s.client.Put(s.ctx, k, &i); err != nil {
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
func (s *GaeSetting) List(site string) map[string]string {
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
func (s *GaeSetting) refreshCache() {
	if s.sites == nil || s.expires.Before(time.Now()) {
		s.sites = s.load()
		s.expires = time.Now().Add(time.Duration(CACHE_TIMEOUT) * time.Second)
	}
}

// Lookup all settings from the database
func (s *GaeSetting) load() map[string]map[string]string {
	all := make(map[string]map[string]string)

	type SI struct {
		Site  string
		Name  string
		Value string
	}
	var entities []SI

	q := datastore.NewQuery("Setting").Limit(1000)
	_, err := s.client.GetAll(s.ctx, q, &entities)
	if err != nil {
		// Handle error
		fmt.Println(err)
		return nil
	}
	if len(entities) == 1000 {
		fmt.Println("Too many entities in settings table. Settings will not operate reliably.")
	}

	for _, e := range entities {
		_, exists := all[e.Site]
		if !exists {
			all[e.Site] = make(map[string]string)
		}
		all[e.Site][e.Name] = e.Value
	}

	return all
}
