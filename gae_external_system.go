// Search, Get, and Update student data. All operations expect a user parameter
// (requestor or updator) to ensure that the person operating on the data has
// the correct permissions. The person operating on data belongs to a specific
// site (virtual host) and operates on data belonging to that persons site.

package security

import (
	"errors"

	"cloud.google.com/go/datastore"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

type GaeExternalSystem struct {
	EUuid   string     `datastore:"Uuid"`
	EType   string     `datastore:"Type"` // Moodle, Blackboard, D2L, Wordpress, Formsite, etc...
	EConfig []KeyValue `datastore:"Config"`
}

func (es *GaeExternalSystem) Type() string {
	return es.EType
}

func (es *GaeExternalSystem) Uuid() string {
	return es.EUuid
}

func (es *GaeExternalSystem) Config() []KeyValue {
	return es.EConfig
}

type GaeExternalSystemId struct {
	externalSystemUuid string `datastore:"ExternalSystemUuid"`
	etype              string `datastore:"Type"` // Moodle,  Formsite, etc
	value              string `datastore:"Value"`
}

func (es *GaeExternalSystemId) Uuid() string {
	return es.externalSystemUuid
}

func (es *GaeExternalSystemId) Type() string {
	return es.etype
}

func (es *GaeExternalSystemId) Value() string {
	return es.value
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

	q := datastore.NewQuery("ExternalSystem").Namespace(requestor.GetSite()).Limit(500)
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

func (am *GaeAccessManager) GetExternalSystem(uuid string, session Session) (ExternalSystem, error) {
	if uuid == "" {
		return nil, errors.New("Invalid UUID")
	}

	k := datastore.NameKey("ExternalSystem", uuid, nil)
	k.Namespace = session.GetSite()

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
	k.Namespace = updator.GetSite()

	if _, err := am.client.Put(am.ctx, k, i); err != nil {
		return nil, err
	}

	return i, nil
}

func (am *GaeAccessManager) DeleteExternalSystem(uuid string, updator Session) error {
	k := datastore.NameKey("ExternalSystem", uuid, nil)
	k.Namespace = updator.GetSite()

	if err := am.client.Delete(am.ctx, k); err != nil {
		return err
	}

	return nil
}

func (am *GaeAccessManager) UpdateExternalSystem(uuid string, config []KeyValue, updator Session) error {
	return errors.New("Unimplemented")
}
