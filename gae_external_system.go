// Search, Get, and Update student data. All operations expect a user parameter
// (requestor or updator) to ensure that the person operating on the data has
// the correct permissions. The person operating on data belongs to a specific
// site (virtual host) and operates on data belonging to that persons site.

package security

import (
	"errors"
	"net/url"
	"strings"

	"cloud.google.com/go/datastore"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

type GaeExternalSystem struct {
	EUuid   string     `datastore:"Uuid"`
	EType   string     `datastore:"Type"` // Moodle, Blackboard, D2L, Wordpress, Formsite, etc...
	EConfig []KeyValue `datastore:"Config,noindex"`
}

func (es *GaeExternalSystem) Type() string {
	return es.EType
}

func (es *GaeExternalSystem) Uuid() string {
	return es.EUuid
}

func (es *GaeExternalSystem) Describe() string {
	for _, e := range es.EConfig {
		val := strings.ToLower(e.Value)
		if strings.HasPrefix(strings.ToLower(e.Value), "http://") || strings.HasPrefix(strings.ToLower(e.Value), "https://") {
			u, err := url.Parse(val)
			if err == nil && u.Hostname() != "" {
				return u.Hostname()
			}

			return val
		}
	}
	if len(es.EConfig) > 0 {
		return es.EConfig[0].Value
	}
	return es.EType
}

func (es *GaeExternalSystem) Config() []KeyValue {
	return es.EConfig
}

func (es *GaeExternalSystem) GetConfig(key string) string {
	key = Underscorify(key)
	for _, k := range es.EConfig {
		if key == Underscorify(k.Key) {
			return k.Value
		}
	}
	return ""
}

func (es *GaeExternalSystem) SetConfig(key, value string) {
	ukey := Underscorify(key)
	if value == "" {
		del := -1
		for i, k := range es.EConfig {
			if ukey == Underscorify(k.Key) {
				del = i
				break
			}
		}
		if del >= 0 {
			es.EConfig = append(es.EConfig[:del], es.EConfig[del+1:]...)
		}
		return
	}
	for _, k := range es.EConfig {
		if ukey == Underscorify(k.Key) {
			k.Value = value
			return
		}
	}
	es.EConfig = append(es.EConfig, KeyValue{key, value})
}

type GaeExternalSystemId struct {
	EExternalSystemUuid string `datastore:"ExternalSystemUuid"`
	EType               string `datastore:"Type"` // Moodle,  Formsite, etc
	EValue              string `datastore:"Value"`
}

func (es *GaeExternalSystemId) ExternalSystemUuid() string {
	return es.EExternalSystemUuid
}

func (es *GaeExternalSystemId) Type() string {
	return es.EType
}

func (es *GaeExternalSystemId) Value() string {
	return es.EValue
}

func (es *GaeExternalSystemId) SetValue(v string) {
	es.EValue = v
}

func NewGaeExternalSystemId(i ExternalSystemId) *GaeExternalSystemId {
	return &GaeExternalSystemId{
		EExternalSystemUuid: i.ExternalSystemUuid(),
		EType:               i.Type(),
		EValue:              i.Value(),
	}
}

func (am *GaeAccessManager) GetExternalSystemsByType(etype string, requestor Session) ([]ExternalSystem, error) {
	results, err := am.GetExternalSystems(requestor)
	if err != nil {
		return nil, err
	}
	var items []ExternalSystem

	for _, result := range results {
		if result.Type() == etype {
			items = append(items, result)
		}
	}

	return items[:], nil
}

func (am *GaeAccessManager) GetExternalSystems(requestor Session) ([]ExternalSystem, error) {
	var items []ExternalSystem

	q := datastore.NewQuery("ExternalSystem").Namespace(requestor.Site()).Limit(500)
	it := am.client.Run(am.ctx, q)
	for {
		e := new(GaeExternalSystem)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		items = append(items, e)
	}

	return items[:], nil
}

func (am *GaeAccessManager) GetExternalSystemCached(uuid string, session Session) (ExternalSystem, error) {
	if uuid == "" {
		return nil, errors.New("Invalid UUID")
	}

	r, _ := am.systemCache.Get(uuid)
	if r != nil {
		return r.(ExternalSystem), nil
	}

	es, err := am.GetExternalSystem(uuid, session)
	if err == nil && es != nil {
		am.systemCache.Set(uuid, es)
	}

	return es, err
}

func (am *GaeAccessManager) GetExternalSystem(uuid string, session Session) (ExternalSystem, error) {
	if uuid == "" {
		return nil, errors.New("Invalid UUID")
	}

	k := datastore.NameKey("ExternalSystem", uuid, nil)
	k.Namespace = session.Site()

	i := new(GaeExternalSystem)
	err := am.client.Get(am.ctx, k, i)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (am *GaeAccessManager) AddExternalSystem(etype string, config []KeyValue, updator Session) (ExternalSystem, error) {
	uuid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	i := &GaeExternalSystem{
		EUuid:   uuid.String(),
		EType:   etype,
		EConfig: config,
	}

	k := datastore.NameKey("ExternalSystem", i.Uuid(), nil)
	k.Namespace = updator.Site()

	if _, err := am.client.Put(am.ctx, k, i); err != nil {
		return nil, err
	}

	return i, nil
}

func (am *GaeAccessManager) DeleteExternalSystem(uuid string, updator Session) error {
	k := datastore.NameKey("ExternalSystem", uuid, nil)
	k.Namespace = updator.Site()

	if err := am.client.Delete(am.ctx, k); err != nil {
		return err
	}

	return nil
}

func (am *GaeAccessManager) UpdateExternalSystem(uuid string, config []KeyValue, updator Session) error {
	return errors.New("Unimplemented")
}
