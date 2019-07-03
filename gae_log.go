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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zaddok/log"

	"cloud.google.com/go/datastore"
)

type LogCollection interface {
	GetUuid() string
	GetComponent() string
	GetBegan() *time.Time
	GetCompleted() *time.Time
	GetPersonUuid() string
}

type LogEntry interface {
	GetUuid() string
	GetLogUuid() string
	GetRecorded() time.Time
	GetComponent() string
	GetLevel() string
	GetMessage() string
}
type SystemLog interface {
	GetIP() string
	GetUuid() string
	GetRecorded() time.Time
	GetComponent() string
	GetLevel() string
	GetMessage() string
}

type DatastoreLog struct {
	client    *datastore.Client
	ctx       context.Context
	uuid      string
	component string
	entry     *GaeLogCollection
	user      Session
}

type GaeLogCollection struct {
	Uuid       string
	Component  string
	Began      *time.Time
	Completed  *time.Time
	PersonUuid string
}

func (lec *GaeLogCollection) GetUuid() string {
	return lec.Uuid
}

func (lec *GaeLogCollection) GetComponent() string {
	return lec.Component
}

func (lec *GaeLogCollection) GetBegan() *time.Time {
	return lec.Began
}

func (lec *GaeLogCollection) GetCompleted() *time.Time {
	return lec.Completed
}

func (lec *GaeLogCollection) GetPersonUuid() string {
	return lec.Uuid
}

type GaeLogEntry struct {
	Uuid      string
	LogUuid   string
	Recorded  time.Time
	Component string `datastore:",noindex"`
	Level     string `datastore:",noindex"`
	Message   string `datastore:",noindex"`
}

func (le *GaeLogEntry) GetUuid() string {
	return le.Uuid
}

func (le *GaeLogEntry) GetLogUuid() string {
	return le.LogUuid
}

func (le *GaeLogEntry) GetRecorded() time.Time {
	return le.Recorded
}

func (le *GaeLogEntry) GetComponent() string {
	return le.Component
}

func (le *GaeLogEntry) GetLevel() string {
	return le.Level
}

func (le *GaeLogEntry) GetMessage() string {
	return le.Message
}

type GaeSystemLog struct {
	Recorded  time.Time
	IP        string `datastore:",noindex"`
	Component string `datastore:",noindex"`
	Level     string `datastore:",noindex"`
	Message   string `datastore:",noindex"`
	Uuid      string `datastore:",noindex"`
}

func (le *GaeSystemLog) GetUuid() string {
	return le.Uuid
}

func (le *GaeSystemLog) GetRecorded() time.Time {
	return le.Recorded
}

func (le *GaeSystemLog) GetIP() string {
	return le.IP
}

func (le *GaeSystemLog) GetComponent() string {
	return le.Component
}

func (le *GaeSystemLog) GetLevel() string {
	return le.Level
}

func (le *GaeSystemLog) GetMessage() string {
	return le.Message
}

func NewGaeSyslogBundle(site string, client *datastore.Client, ctx context.Context) *GaeSyslogBundle {
	return &GaeSyslogBundle{site: site, client: client, ctx: ctx}
}

func (am *GaeAccessManager) GetSyslogBundle(site string) SyslogBundle {
	return &GaeSyslogBundle{site: site, client: am.client, ctx: am.ctx}
}

func (am *GaeAccessManager) Debug(session Session, component, message string, args ...interface{}) {
	i := GaeSystemLog{
		Recorded:  time.Now(),
		Component: component,
		IP:        session.IP(),
		Level:     "debug",
		Message:   fmt.Sprintf(message, args...),
	}
	k := datastore.IncompleteKey("SystemLog", nil)
	k.Namespace = session.Site()
	if _, err := am.client.Put(am.ctx, k, &i); err != nil {
		fmt.Println(err)
		fmt.Println(component, session.IP(), i.Level, fmt.Sprintf(message, args...))
	}
}

func (am *GaeAccessManager) Info(session Session, component, message string, args ...interface{}) {
	i := GaeSystemLog{
		Recorded:  time.Now(),
		Component: component,
		IP:        session.IP(),
		Level:     "info",
		Message:   fmt.Sprintf(message, args...),
	}
	k := datastore.IncompleteKey("SystemLog", nil)
	k.Namespace = session.Site()
	if _, err := am.client.Put(am.ctx, k, &i); err != nil {
		fmt.Println(err)
		fmt.Println(component, session.IP(), i.Level, fmt.Sprintf(message, args...))
	}
}

func (am *GaeAccessManager) Notice(session Session, component, message string, args ...interface{}) {
	i := GaeSystemLog{
		Recorded:  time.Now(),
		Component: component,
		IP:        session.IP(),
		Level:     "notice",
		Message:   fmt.Sprintf(message, args...),
	}
	k := datastore.IncompleteKey("SystemLog", nil)
	k.Namespace = session.Site()
	if _, err := am.client.Put(am.ctx, k, &i); err != nil {
		fmt.Println(err)
		fmt.Println(component, session.IP(), i.Level, fmt.Sprintf(message, args...))
	}
}

func (am *GaeAccessManager) Warning(session Session, component, message string, args ...interface{}) {
	i := GaeSystemLog{
		Recorded:  time.Now(),
		Component: component,
		IP:        session.IP(),
		Level:     "warning",
		Message:   fmt.Sprintf(message, args...),
	}
	k := datastore.IncompleteKey("SystemLog", nil)
	k.Namespace = session.Site()
	if _, err := am.client.Put(am.ctx, k, &i); err != nil {
		fmt.Println(err)
		fmt.Println(component, session.IP(), i.Level, fmt.Sprintf(message, args...))
	}
}

func (am *GaeAccessManager) Error(session Session, component, message string, args ...interface{}) {
	i := GaeSystemLog{
		Recorded:  time.Now(),
		Component: component,
		IP:        session.IP(),
		Level:     "error",
		Message:   fmt.Sprintf(message, args...),
	}
	k := datastore.IncompleteKey("SystemLog", nil)
	k.Namespace = session.Site()
	if _, err := am.client.Put(am.ctx, k, &i); err != nil {
		fmt.Println(err)
		fmt.Println(component, session.IP(), i.Level, fmt.Sprintf(message, args...))
	}
}

type SyslogBundle interface {
	Put()
	Add(component, ip, level, message string)
}

type GaeSyslogBundle struct {
	client *datastore.Client
	ctx    context.Context
	site   string
	Item   []GaeSystemLog
	Key    []*datastore.Key
}

func (sb *GaeSyslogBundle) Put() {
	if len(sb.Items) > 499 {
		fmt.Println("Syslog bundle greater than 500 entries.")
		sb.Items = sb.Items[0:498]
		sb.Add("datastore", "", "error", "Syslog bundle greater than 500 entries.")
	}
	go func() {
		if _, err := sb.client.PutMulti(sb.ctx, sb.Key, sb.Item); err != nil {
			fmt.Printf("Unable to store system log entries: %v", err)
		}
		fmt.Println("Syslog bundle persisted.", len(sb.Items))
	}()
}

func (sb *GaeSyslogBundle) Add(component, ip, level, message string) {
	i := GaeSystemLog{
		Recorded:  time.Now(),
		Component: component,
		IP:        ip,
		Level:     level,
		Message:   message}
	sb.Item = append(sb.Item, i)
	k := datastore.IncompleteKey("SystemLog", nil)
	k.Namespace = sb.site
	sb.Key = append(sb.Key, k)
}

func NewDatastoreLog(component string, user Session, client *datastore.Client, ctx context.Context) (log.Log, string, error) {
	cuuid, err := uuid.NewRandom()
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	entry := &GaeLogCollection{cuuid.String(), component, &now, nil, user.PersonUuid()}

	k := datastore.NameKey("LogCollection", cuuid.String(), nil)
	k.Namespace = user.Site()
	if _, err := client.Put(ctx, k, entry); err != nil {
		return nil, "", err
	}

	l := &DatastoreLog{client, ctx, cuuid.String(), component, entry, user}
	l.Info("Opened")
	return l, cuuid.String(), nil
}

func (l *DatastoreLog) Close() {

	k := datastore.NameKey("LogCollection", l.uuid, nil)
	k.Namespace = l.user.Site()

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
	k.Namespace = l.user.Site()
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

type GaeEntityAudit struct {
	Date       time.Time
	EntityUuid string
	Attribute  string
	OldValue   string
	NewValue   string
	ValueType  string
	PersonUuid string
	PersonName string
}

func (e *GaeEntityAudit) GetDate() time.Time {
	return e.Date
}

func (e *GaeEntityAudit) GetEntityUuid() string {
	return e.EntityUuid
}

func (e *GaeEntityAudit) GetAttribute() string {
	return e.Attribute
}

func (e *GaeEntityAudit) GetOldValue() string {
	return e.OldValue
}

func (e *GaeEntityAudit) GetNewValue() string {
	return e.NewValue
}

func (e *GaeEntityAudit) GetValueType() string {
	return e.ValueType
}

func (e *GaeEntityAudit) GetDocumentType() string {
	if e.ValueType == "document" {
		i := strings.LastIndex(e.OldValue, "|")
		if i > 0 {
			return e.OldValue[0:i]
		}
	}
	return ""
}

func (e *GaeEntityAudit) GetDocumentFilename() string {
	if e.ValueType == "document" {
		i := strings.LastIndex(e.OldValue, "|")
		if i > 0 {
			f := e.OldValue[i+1:]
			if f != "" {
				return f
			}
			return e.NewValue[i+1:]
		}
	}
	return ""
}

func (e *GaeEntityAudit) GetActionType() string {
	if e.ValueType == "document" {
		i := strings.LastIndex(e.OldValue, "|")
		if i > 0 {
			//docType := e.OldValue[0:i]
			ov := e.OldValue[i+1:]
			nv := e.NewValue[i+1:]
			if ov != "" && nv != "" {
				return "update"
			}
			if ov == "" && nv != "" {
				return "add"
			}
			if ov != "" && nv == "" {
				return "delete"
			}
		}

	}

	if e.OldValue != "" && e.NewValue != "" {
		return "update"
	}
	if e.OldValue == "" && e.NewValue != "" {
		return "add"
	}
	if e.OldValue != "" && e.NewValue == "" {
		return "delete"
	}
	return "other"
}

func (e *GaeEntityAudit) IsPicklistType() bool {
	if e.ValueType == "bool" ||
		e.ValueType == "int64" ||
		e.ValueType == "int" ||
		e.ValueType == "string" ||
		e.ValueType == "money" ||
		e.ValueType == "document" ||
		e.ValueType == "" ||
		e.ValueType == "date" {
		return false
	}
	return true
}

func (e *GaeEntityAudit) GetPersonUuid() string {
	return e.PersonUuid
}

func (e *GaeEntityAudit) GetPersonName() string {
	return e.PersonName
}

type GaeEntityAuditLogCollection struct {
	Uuid       string
	EntityUuid string
	PersonUuid string
	PersonName string
	Date       time.Time
	Items      []GaeEntityAudit
}

func (ec *GaeEntityAuditLogCollection) GetUuid() string {
	return ec.Uuid
}

func (ec *GaeEntityAuditLogCollection) SetEntityUuidPersonUuid(entityUuid, personUuid, personName string) {
	if entityUuid == "" {
		panic(errors.New("Entity UUID must not be empty"))
	}
	if personUuid == "" {
		panic(errors.New("Person UUID must not be empty"))
	}
	ec.EntityUuid = entityUuid
	ec.PersonUuid = personUuid
	ec.PersonName = personName
	ec.Date = time.Now()
}

func (ec *GaeEntityAuditLogCollection) GetPersonUuid() string {
	return ec.PersonUuid
}

func (ec *GaeEntityAuditLogCollection) GetPersonName() string {
	return ec.PersonName
}

func (ec *GaeEntityAuditLogCollection) GetEntityUuid() string {
	return ec.EntityUuid
}

func (ec *GaeEntityAuditLogCollection) GetDate() time.Time {
	return ec.Date
}

func (ec *GaeEntityAuditLogCollection) GetItems() []EntityAudit {
	var i []EntityAudit

	for x, _ := range ec.Items {
		i = append(i, &(ec.Items[x]))
	}

	return i
}

func (ec *GaeEntityAuditLogCollection) AddItem(attribute, oldValue, newValue string) {
	if ec.EntityUuid == "" || ec.PersonUuid == "" {
		panic(errors.New("GaeEntityAuditLogCollection.AddItem() called prior to SetEntityUuidPersonUuid()."))
	}
	ec.Items = append(ec.Items, GaeEntityAudit{ec.Date, ec.EntityUuid, attribute, oldValue, newValue, "string", ec.PersonUuid, ec.PersonName})
}

func (ec *GaeEntityAuditLogCollection) AddPicklistItem(attribute, oldValue, newValue, picklistType string) {
	if ec.EntityUuid == "" || ec.PersonUuid == "" {
		panic(errors.New("GaeEntityAuditLogCollection.AddItem() called prior to SetEntityUuidPersonUuid()."))
	}
	ec.Items = append(ec.Items, GaeEntityAudit{ec.Date, ec.EntityUuid, attribute, oldValue, newValue, picklistType, ec.PersonUuid, ec.PersonName})
}

func (ec *GaeEntityAuditLogCollection) AddDocumentItem(attribute string, documentType, oldValue, newValue string) {
	if ec.EntityUuid == "" || ec.PersonUuid == "" {
		panic(errors.New("GaeEntityAuditLogCollection.AddIntItem() called prior to SetEntityUuidPersonUuid()."))
	}
	ec.Items = append(ec.Items, GaeEntityAudit{ec.Date, ec.EntityUuid, attribute, documentType + "|" + oldValue, documentType + "|" + newValue, "document", ec.PersonUuid, ec.PersonName})
}

func (ec *GaeEntityAuditLogCollection) AddIntItem(attribute string, oldValue, newValue int64) {
	if ec.EntityUuid == "" || ec.PersonUuid == "" {
		panic(errors.New("GaeEntityAuditLogCollection.AddIntItem() called prior to SetEntityUuidPersonUuid()."))
	}
	ec.Items = append(ec.Items, GaeEntityAudit{ec.Date, ec.EntityUuid, attribute, fmt.Sprintf("%v", oldValue), fmt.Sprintf("%v", newValue), "int64", ec.PersonUuid, ec.PersonName})
}

func (ec *GaeEntityAuditLogCollection) AddFloatItem(attribute string, oldValue, newValue float64) {
	if ec.EntityUuid == "" || ec.PersonUuid == "" {
		panic(errors.New("GaeEntityAuditLogCollection.AddIntItem() called prior to SetEntityUuidPersonUuid()."))
	}
	ec.Items = append(ec.Items, GaeEntityAudit{ec.Date, ec.EntityUuid, attribute, fmt.Sprintf("%v", oldValue), fmt.Sprintf("%v", newValue), "float64", ec.PersonUuid, ec.PersonName})
}

func (ec *GaeEntityAuditLogCollection) AddMoneyItem(attribute string, oldValue, newValue int64) {
	if ec.EntityUuid == "" || ec.PersonUuid == "" {
		panic(errors.New("GaeEntityAuditLogCollection.AddMoneyItem() called piror to SetEntityUuidPersonUuid()."))
	}
	ec.Items = append(ec.Items, GaeEntityAudit{ec.Date, ec.EntityUuid, attribute, fmt.Sprintf("$%0.2f", (float64(oldValue) / 100.0)), fmt.Sprintf("$%0.2f", (float64(newValue) / 100.0)), "money", ec.PersonUuid, ec.PersonName})
}

func (ec *GaeEntityAuditLogCollection) AddBoolItem(attribute string, oldValue, newValue bool) {
	if ec.EntityUuid == "" || ec.PersonUuid == "" {
		panic(errors.New("GaeEntityAuditLogCollection.AddItem() called prior to SetEntityUuidPersonUuid()."))
	}
	ec.Items = append(ec.Items, GaeEntityAudit{ec.Date, ec.EntityUuid, attribute, fmt.Sprintf("%v", oldValue), fmt.Sprintf("%v", newValue), "bool", ec.PersonUuid, ec.PersonName})
}

func (ec *GaeEntityAuditLogCollection) AddDateItem(attribute string, oldValue, newValue *time.Time) {
	if ec.EntityUuid == "" || ec.PersonUuid == "" {
		panic(errors.New("GaeEntityAuditLogCollection.AddDateItem() called prior to SetEntityUuidPersonUuid()."))
	}
	ov := ""
	nv := ""
	if oldValue != nil {
		ov = oldValue.Format("2006-01-02 15:04.05")
	}
	if newValue != nil {
		nv = newValue.Format("2006-01-02 15:04.05")
	}
	ec.Items = append(ec.Items, GaeEntityAudit{ec.Date, ec.EntityUuid, attribute, ov, nv, "date", ec.PersonUuid, ec.PersonName})
}

func (ec *GaeEntityAuditLogCollection) HasUpdates() bool {
	return len(ec.Items) > 0
}
