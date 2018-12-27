// Provides a Log interface that can be used to wrap other logging
// interfaces to allow swapping out log interfaces.
//
// Log to stdout:
//
//    log := NewStdoutLog()
//    log.Error("My name is: %s", name)
//
// Log using syslog:
//
//    log, err := log.NewLog("myapp")
//    if err != nil {
//        fmt.Fprintln(os.Stderr, "Failure to setup syslog logging: %v", err)
//        os.Exit(1)
//    }
//    log.Error("My name is: %s", name)
//
package security

import (
	"cloud.google.com/go/datastore"
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/zaddok/log"
	"time"
)

type DatastoreLog struct {
	client    *datastore.Client
	ctx       context.Context
	uuid      string
	component string
	entry     *GaeLogEntryCollection
	user      Session
}

type GaeLogEntryCollection struct {
	Uuid       string
	Component  string
	Began      *time.Time
	Completed  *time.Time
	PersonUuid string
}

type GaeLogEntry struct {
	Uuid      string
	LogUuid   string
	Recorded  time.Time
	Component string
	Level     string
	Message   string
}

func NewDatastoreLog(component string, user Session, client *datastore.Client, ctx context.Context) (log.Log, string, error) {
	cuuid, err := uuid.NewRandom()
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	entry := &GaeLogEntryCollection{cuuid.String(), component, &now, nil, user.GetPersonUuid()}

	k := datastore.NameKey("LogEntryCollection", cuuid.String(), nil)
	k.Namespace = user.GetSite()
	if _, err := client.Put(ctx, k, entry); err != nil {
		return nil, "", err
	}

	l := &DatastoreLog{client, ctx, cuuid.String(), component, entry, user}
	l.Info("Opened")
	return l, cuuid.String(), nil
}

func (l *DatastoreLog) Close() {

	k := datastore.NameKey("LogEntryCollection", l.uuid, nil)
	k.Namespace = l.user.GetSite()

	now := time.Now()
	l.entry.Completed = &now
	l.Info("Closed")

	if _, err := l.client.Put(l.ctx, k, l.entry); err != nil {
		fmt.Println("Log close filed: ", err)
	}
}

func (l *DatastoreLog) Debug(format string, a ...interface{}) error {
	return l.doLog("DEBUG", fmt.Sprintf(format, a...))
}

func (l *DatastoreLog) doLog(level string, message string) error {
	fmt.Println(l.component + " " + level + ": " + message)

	uuid, err := uuid.NewRandom()
	if err != nil {
		return err
	}

	var entry GaeLogEntry
	entry.Uuid = uuid.String()
	entry.LogUuid = l.uuid
	entry.Component = l.component
	entry.Level = level
	entry.Recorded = time.Now()
	entry.Message = message

	k := datastore.NameKey("LogEntry", uuid.String(), nil)
	k.Namespace = l.user.GetSite()
	if _, err := l.client.Put(l.ctx, k, &entry); err != nil {
		return err
	}
	return nil
}

func (l *DatastoreLog) Info(format string, a ...interface{}) error {
	return l.doLog("INFO", fmt.Sprintf(format, a...))
}

func (l *DatastoreLog) Notice(format string, a ...interface{}) error {
	return l.doLog("NOTICE", fmt.Sprintf(format, a...))
}

func (l *DatastoreLog) Warning(format string, a ...interface{}) error {
	return l.doLog("WARN", fmt.Sprintf(format, a...))
}

func (l *DatastoreLog) Error(format string, a ...interface{}) error {
	return l.doLog("ERROR", fmt.Sprintf(format, a...))
}
