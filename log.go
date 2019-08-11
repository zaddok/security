// There are three types of log objects used for three different purposes.
//  1. LogCollection holds log entries returned by a batch job or task.
//  2. SystemLog holds log entries related to user activity in the system.
//  3. EndityChangeLog logs changes to attributes of objects.
package security

import (
	"time"
)

// LogCollection holds a sequence of LogEntry items produced by a batch job or task for later inspection
type LogCollection interface {
	GetUuid() string
	GetComponent() string
	GetBegan() *time.Time
	GetCompleted() *time.Time
	GetPersonUuid() string
}

// LogEntry holds a log item belonging to a LogCollection
type LogEntry interface {
	GetUuid() string
	GetLogUuid() string
	GetRecorded() time.Time
	GetComponent() string
	GetLevel() string
	GetMessage() string
}

// SystemLog records information about an action of a user in the system
type SystemLog interface {
	GetIP() string
	GetUuid() string
	GetPersonUuid() string
	GetRecorded() time.Time
	GetComponent() string
	GetLevel() string
	GetMessage() string
}

// SyslogBundle caches a sequence of SystemLog entities for bulk writing to the data store.
type SyslogBundle interface {
	Put()
	Add(component, ip, level, message string)
}

// EntityChange records changes to attributes of an object, who changed the attribute, and when.
type EntityChange interface {
}

// EntityChangeLog holds a batch of EntityChange objects, supporting a bulk commit of these changes
type EntityChangeLog interface {
}
