package security

import (
	"encoding/json"
	"time"
)

type KeyValue struct {
	Key   string
	Value string
}

type ConnectorFunction func(AccessManager, *ScheduledConnector, Session) error

type ConnectorInfo struct {
	SystemType  string // Moodle, GoogleSheets, Formsite
	SystemIcon  string
	DataType    string // Subject, Student, Course, etc...
	Name        string
	Description string // Description of the purpose of this connector
	Label       string
	Direction   int
	Config      [][]string
	Run         func(AccessManager, *ScheduledConnector, Session) error
}

type ScheduledConnector struct {
	Uuid               string      `json:",omitempty"`
	ExternalSystemUuid string      `json:",omitempty"`
	Label              string      `json:",omitempty"`
	Config             []*KeyValue `json:",omitempty"`
	Data               []*KeyValue `json:",omitempty"`
	Frequency          string      `json:",omitempty"` // daily, hourly, weekly
	Hour               int         `json:",omitempty"` // if hourly/weekly, what hour
	Day                int         `json:",omitempty"` // if weekly, what day
	LastRun            *time.Time  `json:",omitempty"`

	// Describes the configuration of this connector. i.e. Where do we connect to? What server? What domain? etc...
	Description string `json:",omitempty"`

	Disabled bool
}

func (sc *ScheduledConnector) GetConfig(key string) string {
	key = Underscorify(key)
	for _, k := range sc.Config {
		if key == Underscorify(k.Key) {
			return k.Value
		}
	}
	return ""
}

func (s *ScheduledConnector) String() string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (sc *ScheduledConnector) SetConfig(key, value string) {
	ukey := Underscorify(key)
	if value == "" {
		del := -1
		for i, k := range sc.Config {
			if ukey == Underscorify(k.Key) {
				del = i
				break
			}
		}
		if del >= 0 {
			sc.Config = append(sc.Config[:del], sc.Config[del+1:]...)
		}
		return
	}
	for _, k := range sc.Config {
		if ukey == Underscorify(k.Key) {
			k.Value = value
			return
		}
	}
	sc.Config = append(sc.Config, &KeyValue{key, value})
}

func (sc *ScheduledConnector) GetData(key string) string {
	key = Underscorify(key)
	for _, k := range sc.Data {
		if key == Underscorify(k.Key) {
			return k.Value
		}
	}
	return ""
}

func (sc *ScheduledConnector) SetData(key, value string) {
	ukey := Underscorify(key)
	if value == "" {
		del := -1
		for i, k := range sc.Data {
			if ukey == Underscorify(k.Key) {
				del = i
				break
			}
		}
		if del >= 0 {
			sc.Data = append(sc.Data[:del], sc.Data[del+1:]...)
		}
		return
	}
	for _, k := range sc.Data {
		if ukey == Underscorify(k.Key) {
			k.Value = value
			return
		}
	}
	sc.Data = append(sc.Data, &KeyValue{key, value})
}
