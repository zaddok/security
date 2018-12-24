package security

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
)

type GaePicklistStore struct {
	client    *datastore.Client
	ctx       context.Context
	expires   time.Time
	picklists map[string]map[string]map[string]PicklistItem //host -> picklist -> values
}

type GaePicklistItem struct {
	Picklist    string
	Key         string
	Value       string
	Description string
	Deprecated  bool
}

func (pi *GaePicklistItem) GetKey() string {
	return pi.Key
}

func (pi *GaePicklistItem) GetValue() string {
	return pi.Value
}

func (pi *GaePicklistItem) GetDescription() string {
	return pi.Description
}

func (pi *GaePicklistItem) IsDeprecated() bool {
	return pi.Deprecated
}

func NewGaePicklistStore(projectID string, client *datastore.Client, ctx context.Context) PicklistStore {
	ps := &GaePicklistStore{
		client: client,
		ctx:    ctx,
	}
	return ps
}

func (s *GaePicklistStore) GetPicklists(site string) (map[string]map[string]PicklistItem, error) {
	err := s.refreshCache(site)
	if err != nil {
		return nil, err
	}

	return nil, errors.New("Unimeplmented")
}

// Lookup a configuration setting. Loads from database only if cache has expired.
func (s *GaePicklistStore) GetPicklist(site, picklist string) (map[string]PicklistItem, error) {
	err := s.refreshCache(site)
	if err != nil {
		return nil, err
	}

	sitePicklists, exists := s.picklists[site]
	if !exists {
		return nil, nil
	}

	value, exists := sitePicklists[strings.ToLower(picklist)]
	if exists {
		return value, nil
	}

	return nil, nil
}

// Lookup a configuration setting. Loads from database only if cache has expired.
func (s *GaePicklistStore) GetPicklistItem(site, picklist, key string) (PicklistItem, error) {
	pl, err := s.GetPicklist(site, picklist)
	if err != nil {
		return nil, err
	}

	value, exists := pl[strings.ToLower(key)]
	if exists {
		return value, nil
	}

	i := &GaePicklistItem{Picklist: picklist, Key: key, Deprecated: false}
	return i, nil
}

// Store a configuration setting. Stores in cache, and flushes through to database.
func (s *GaePicklistStore) DeprecatePicklistItem(site, picklist, key string) error {
	//picklist = strings.ToLower(picklist)
	//key = strings.ToLower(key)

	return nil
}

// Store a configuration setting. Stores in cache, and flushes through to database.
func (s *GaePicklistStore) AddPicklistItem(site, picklist, key, value, description string) error {
	picklist = strings.ToLower(picklist)
	key = strings.ToLower(key)

	k := datastore.NameKey("PicklistItem", picklist+"|"+key, nil)
	k.Namespace = site
	i := &GaePicklistItem{Picklist: picklist, Key: key, Value: value, Description: description, Deprecated: false}
	if _, err := s.client.Put(s.ctx, k, i); err != nil {
		return err
	}

	// Get the sites full picklists set
	if s.picklists == nil {
		s.picklists = make(map[string]map[string]map[string]PicklistItem)
	}
	_, exists := s.picklists[site]
	if !exists {
		s.picklists[site] = make(map[string]map[string]PicklistItem)
	}

	_, exists = s.picklists[site][picklist]
	if !exists {
		s.picklists[site][picklist] = make(map[string]PicklistItem)
	}

	s.picklists[site][picklist][key] = i

	return nil
}

// Reload settings from cache if cache has expired
func (s *GaePicklistStore) refreshCache(site string) error {
	fmt.Printf("refreshCache(\"%s\")\n", site)
	if s.picklists == nil || s.picklists[site] == nil || s.expires.Before(time.Now()) {
		if s.picklists == nil {
			s.picklists = make(map[string]map[string]map[string]PicklistItem)
			s.expires = time.Now().Add(time.Duration(PICKLIST_CACHE_TIMEOUT) * time.Second)
		}
		rs, err := s.load(site)
		if err != nil {
			s.picklists = nil
			return err
		}
		s.picklists[site] = rs
	}

	return nil
}

// Lookup all settings from the database
func (s *GaePicklistStore) load(site string) (map[string]map[string]PicklistItem, error) {
	fmt.Printf("load(\"%s\")\n", site)
	all := make(map[string]map[string]PicklistItem)

	var items []*GaePicklistItem

	q := datastore.NewQuery("PicklistItem").Namespace(site).Limit(3000)
	_, err := s.client.GetAll(s.ctx, q, &items)
	if err != nil {
		return nil, err
	}
	if len(items) == 3000 {
		fmt.Println("Too many entities in settings table. Settings will not operate reliably.")
	}

	fmt.Println(len(items))
	for _, e := range items {
		fmt.Println(e)
		_, exists := all[e.Picklist]
		if !exists {
			all[e.Picklist] = make(map[string]PicklistItem)
		}
		all[e.Picklist][e.Key] = e
	}

	return all, nil
}
