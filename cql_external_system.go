// Search, Get, and Update student data. All operations expect a user parameter
// (requestor or updator) to ensure that the person operating on the data has
// the correct permissions. The person operating on data belongs to a specific
// site (virtual host) and operates on data belonging to that persons site.

package security

import (
	"errors"
)

type CqlExternalSystem struct {
	uuid   string     `json:",omitempty"`
	etype  string     `json:"type,omitempty", datastore:"type"` // Moodle, Blackboard, D2L, Wordpress, Formsite, etc...
	config []KeyValue `json:",omitempty"`
}

func (es *CqlExternalSystem) Type() string {
	return es.etype
}

func (es *CqlExternalSystem) Uuid() string {
	return es.uuid
}

func (es *CqlExternalSystem) Config() []KeyValue {
	return es.config
}

type CqlExternalSystemId struct {
	externalSystemUuid string `json:",omitempty"`
	etype              string `json:"type,omitempty", datastore:"type"` // Moodle,  Formsite, etc
	value              string `json:",omitempty"`
}

func (es *CqlExternalSystemId) Uuid() string {
	return es.externalSystemUuid
}

func (es *CqlExternalSystemId) Type() string {
	return es.etype
}

func (es *CqlExternalSystemId) Value() string {
	return es.value
}

func (sis *CqlAccessManager) GetExternalSystemsByType(etype string, requestor Session) ([]ExternalSystem, error) {
	return nil, errors.New("Unimplemented")
}

func (sis *CqlAccessManager) GetExternalSystems(requestor Session) ([]ExternalSystem, error) {
	return nil, errors.New("Unimplemented")
}

func (sis *CqlAccessManager) GetExternalSystem(uuid string, session Session) (ExternalSystem, error) {
	return nil, errors.New("Unimplemented")
}

func (sis *CqlAccessManager) AddExternalSystem(etype string, config []KeyValue, updator Session) (ExternalSystem, error) {
	return nil, errors.New("Unimplemented")
}

func (sis *CqlAccessManager) DeleteExternalSystem(uuid string, updator Session) error {
	return errors.New("Unimplemented")
}

func (sis *CqlAccessManager) UpdateExternalSystem(uuid string, config []KeyValue, updator Session) error {
	return errors.New("Unimplemented")
}
