package security

import (
	"time"
)

type VirtualHostSetup func(site string, am AccessManager)

type AccessManager interface {
	Signup(host, first_name, last_name, email, password, ip string) (*[]string, string, error)
	ActivateSignup(host, token, ip string) (string, string, error)
	ForgotPasswordRequest(host, email, ip string) (string, error)
	ResetPassword(host, token, password, ip string) (bool, string, error)
	Authenticate(host, email, password, ip string) (Session, string, error)

	GetPerson(uuid string, requestor Session) (Person, error)
	GetPersonByFirstNameLastName(site, firstname, lastname string, requestor Session) (Person, error)
	GetPersonByEmail(site, email string, requestor Session) (Person, error)
	GetPeople(requestor Session) ([]Person, error)

	// AddPerson creates a new user account. Email must be unique. Password must already be hashed, or nil. Returns the uuid of the created account
	AddPerson(site, firstName, lastName, email, roles string, password *string, ip string, requestor Session) (string, error)
	UpdatePerson(uuid, firstName, lastName, email, roles, password string, updator Session) error
	DeletePerson(uuid string, updator Session) error
	SearchPeople(keyword string, requestor Session) ([]Person, error)
	CheckEmailExists(site, email string) (bool, error)

	Session(host, ip, cookie string) (Session, error)
	GuestSession(site, ip string) Session
	Invalidate(host, ip, cookie string) (Session, error)
	GetSystemSession(host, firstname, lastname string) (Session, error)
	GetSystemSessionWithRoles(host, firstname, lastname, roles string) (Session, error)

	Setting() Setting
	PicklistStore() PicklistStore
	SetVirtualHostSetupHandler(fn VirtualHostSetup)
	RunVirtualHostSetupHandler(site string)
	CreateTask(queueID, message string) (string, error)

	GetCustomRoleTypes() []RoleType
	AddCustomRoleType(uid, name, description string)

	GetSyslogBundle(site string) SyslogBundle
	GetRecentSystemLog(requestor Session) ([]SystemLog, error)
	GetRecentLogCollections(requestor Session) ([]LogCollection, error)
	GetLogCollection(uuid string, requestor Session) ([]LogEntry, error)

	GetExternalSystems(requestor Session) ([]ExternalSystem, error)
	GetExternalSystemsByType(etype string, requestor Session) ([]ExternalSystem, error)
	GetExternalSystem(uuid string, requestor Session) (ExternalSystem, error)
	AddExternalSystem(etype string, config []KeyValue, updator Session) (ExternalSystem, error)
	UpdateExternalSystem(uuid string, config []KeyValue, updator Session) error
	DeleteExternalSystem(uuid string, updator Session) error

	// StartWatching records that a user is interested in notifications when an
	// event of interest occurs
	StartWatching(objectUuid, objectName, objectType string, user Session) error

	// StopWatching registers that a user is no longer interested in notifications
	// when an event of interest occurs
	StopWatching(objectUuid, objectType string, requestor Session) error

	// GetWatching returns the list of objects the current user is watching
	GetWatching(requestor Session) ([]Watch, error)

	// GetWatchers returns the list of users watching this object
	GetWatchers(objectUuid string, requestor Session) ([]Watch, error)

	// TriggerNotificationEvent is called when an object that is potentially being monitered is updated.
	// It is reponsible for examining who may need to be notified and invoke any event handlers
	TriggerNotificationEvent(objectUuid string, session Session) error
	RegisterNotificationEventHandler(handler NotificationEventHandler)
	RegisterAuthenticationHandler(handler AuthenticationHandler)
	RegisterPreAuthenticationHandler(handler PreAuthenticationHandler)

	GetConnectorInfo() []*ConnectorInfo
	GetConnectorInfoByLabel(label string) *ConnectorInfo
	RegisterConnectorInfo(connector *ConnectorInfo)

	GetEntityChangeLog(uuid string, requestor Session) ([]EntityAuditLogCollection, error)
	AddEntityChangeLog(ec EntityAuditLogCollection, requestor Session) error

	GetScheduledConnectors(requestor Session) ([]*ScheduledConnector, error)
	GetScheduledConnector(uuid string, requestor Session) (*ScheduledConnector, error)
	AddScheduledConnector(connector *ScheduledConnector, updator Session) error
	UpdateScheduledConnector(connector *ScheduledConnector, updator Session) error
	DeleteScheduledConnector(uuid string, updator Session) error

	WipeDatastore(namespace string) error

	Syslogger
}

type Syslogger interface {
	Debug(session Session, component, message string, args ...interface{})
	Info(session Session, component, message string, args ...interface{})
	Notice(session Session, component, message string, args ...interface{})
	Warning(session Session, component, message string, args ...interface{})
	Error(session Session, component, message string, args ...interface{})
}

// Information about a verified user
type Person interface {
	Uuid() string
	Site() string
	FirstName() string
	LastName() string
	Email() string
	Roles() []string
	LastSignin() *time.Time
	LastSigninIP() string
	Created() *time.Time
	DisplayName() string
	HasRole(uid string) bool
}

// Encapsulates an as yet unverified request. i.e. Account creation.
type Verification interface {
	Token() string
	Data() string
}

// Contains information about a currently authenticated user session
type Session interface {
	Site() string
	IP() string
	Token() string
	PersonUuid() string
	CSRF() string
	FirstName() string
	LastName() string
	DisplayName() string
	Email() string
	IsAuthenticated() bool
	HasRole(uid string) bool
}

type RoleType interface {
	GetUid() string
	GetName() string
	GetDescription() string
}

type Watch interface {
	GetObjectUuid() string
	GetObjectName() string
	GetObjectType() string
	GetPersonUuid() string
	GetPersonName() string
}

type NewUserInfo struct {
	Site      string  `json:"site"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	Email     string  `json:"email"`
	Password  *string `json:"password"`
}

// EntityAudit represents information about who changed the value
// of an attribute, how it was changed, and when it was changed.
// It is anticipated that this object type enables display of log messages in the form:
//
// {{Date}}: {{Person Name}} updated {{Attribute}} from {{Old value}} to {{new value}}
//
// This will perform well only on entities that are not continually changing, i.e. Personal
// detais of user accounts, contact details, etc...
type EntityAudit interface {
	GetAttribute() string
	GetOldValue() string
	GetNewValue() string
	GetValueType() string
	IsPicklistType() bool
	GetActionType() string
	GetDocumentType() string
	GetDocumentFilename() string
}

// EntityAuditLogCollection defines an interface used by the BulkUpdateEntityAuditLog() function.
// It facilitates collecting together multiple updates to be persisted in one operation.
type EntityAuditLogCollection interface {

	// A unique identifier for this particular change
	GetUuid() string

	// The entity in the system that has been altered
	GetEntityUuid() string
	GetPersonUuid() string
	GetPersonName() string
	GetDate() time.Time
	GetItems() []EntityAudit

	SetEntityUuidPersonUuid(entityUuid, personUuid, personName string)
	AddItem(attribute, oldValue, newValue string)
	AddIntItem(attribute string, oldValue, newValue int64)
	AddFloatItem(attribute string, oldValue, newValue float64)
	AddMoneyItem(attribute string, oldValue, newValue int64)
	AddDateItem(attribute string, oldValue, newValue *time.Time)
	AddBoolItem(attribute string, oldValue, newValue bool)
	AddPicklistItem(attribute string, oldValue, newValue, valueType string)
	HasUpdates() bool
}

type ExternalSystem interface {
	Type() string
	Uuid() string
	Config() []KeyValue

	GetConfig(key string) string
	SetConfig(key, value string)

	// Describe returns a brief string that will identify the external system against another one.
	Describe() string
}

type ExternalSystemId interface {
	ExternalSystemUuid() string
	Type() string
	Value() string
}

// Check an email (username)  and password against an external authentication source
type AuthenticationHandler func(AccessManager, string, string) (bool, error)

// Signal that an email address is about to be sent to the Authentication method for a particular site.
// Can be used to trigger 'just in time' account creation. Error will block signin,
// avoid returning an error unless it should genuinely block authentication.
type PreAuthenticationHandler func(AccessManager, string, string) error

// Register a callback handler when a an event occurs on a particular atched item
type NotificationEventHandler func(watch Watch, updator Session, am AccessManager) (bool, error)

const emailHtmlTemplates string = `
{{define "signup_confirmation_html"}}
<p>
Hi {{.FirstName}},
</p>

<p>
Thanks for signing up, please use the link below to confirm that your account
details are all correct.
</p>

<p>
<b>Name:</b> {{.FirstName}} {{.LastName}}<br/>
<b>Email:</b> {{.ToEmail}}
<p>

<p>
<a href="{{.BaseURL}}/activate/{{.Token}}">{{.BaseURL}}/activate/{{.Token}}</a>
</p>

<p>
This URL will expire in 24 hours. If you don't want an account to be setup, feel
free to simply ignore this email.
</p>
{{end}}

{{define "signup_confirmation_text"}}
Hi {{.FirstName}},

Thanks for signing up, please use the link below to confirm that your account
details are all correct.

  Name: {{.FirstName}} {{.LastName}}
  Email: {{.ToEmail}}

  {{.BaseURL}}/activate/{{.Token}}

This URL will expire in 24 hours. If you don't want an account to be setup, feel
free to simply ignore this email.
{{end}}

{{define "lost_password_html"}}
<p>
Hi {{.FirstName}},
</p>

<p>
We received a request to reset the password for your account, if this request
was initiated by you, then you can go ahead and reset your password at the
link below. This link will expire in 24 hours.
</p>

<p>
<b>Name:</b> {{.FirstName}} {{.LastName}}<br/>
<b>Email:</b> {{.ToEmail}}
<p>

<p>
<a href="{{.BaseURL}}/reset.password/{{.Token}}">{{.BaseURL}}/reset.password/{{.Token}}</a>
</p>

<p>
If you did not initiate this password reset request, no action is required,
simply ignore this email.
</p>
{{end}}

{{define "lost_password_text"}}
Hi {{.FirstName}},

We received a request to reset the password for your account, if this request
was initiated by you, then you can go ahead and reset your password at the
link below. This link will expire in 24 hours.

  Name: {{.FirstName}} {{.LastName}}
  Email: {{.ToEmail}}

  {{.BaseURL}}/reset.password/{{.Token}}

If you did not initiate this password reset request, no action is required,
simply ignore this email.
{{end}}
`
