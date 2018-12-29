package security

import (
	"github.com/zaddok/log"
)

type AccessManager interface {
	Signup(host, first_name, last_name, email, password, ip string) (*[]string, string, error)
	GetPersonByFirstNameLastName(site, firstname, lastname string) (Person, error)
	AddPerson(site, firstName, lastName, email string, password *string) (string, error)
	ActivateSignup(host, token, ip string) (string, string, error)
	ForgotPasswordRequest(host, email, ip string) (string, error)
	Authenticate(host, email, password, ip string) (Session, string, error)

	Session(host, cookie string) (Session, error)
	GuestSession(site string) Session
	Invalidate(host, cookie string) (Session, error)
	CreateSession(site string, uuid string, firstName string, lastName string, email string, ip string) (string, error)
	GetSystemSession(host, firstname, lastname string) (Session, error)

	Log() log.Log
	Setting() Setting
	PicklistStore() PicklistStore
	GetRecentLogCollections(requestor Session) ([]LogCollection, error)
	GetLogCollection(uuid string, requestor Session) ([]LogEntry, error)
	WipeDatastore(namespace string) error
}

// Information about a verified user
type Person interface {
	GetUuid() string
	GetSite() string
	GetFirstName() string
	GetLastName() string
	GetEmail() string
}

// Encapsulates an as yet unverified request. i.e. Account creation.
type Verification interface {
	Token() string
	Data() string
}

// Contains information about a currently authenticated user session
type Session interface {
	GetPersonUuid() string
	GetToken() string
	GetSite() string
	GetFirstName() string
	GetLastName() string
	GetEmail() string
	IsAuthenticated() bool
}

type NewUserInfo struct {
	Site      string  `json:"site"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	Email     string  `json:"email"`
	Password  *string `json:"password"`
}

const emailHtmlTemplates string = `
{{define "signup_confirmation_html"}}
<p>
Dear {{.FirstName}} {{.LastName}},
</p>

<p>
Thanks for signing up, please use the link below to confirm that your account
details are all correct.
</p>

<p>
<b>Name:</b> {{.FirstName}} {{.LastName}}<br/>
<b>Email:</b> {{.Email}}
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
Dear {{.FirstName}} {{.LastName}}

Thanks for signing up, please use the link below to confirm that your account
details are all correct.

  Name: {{.FirstName}} {{.LastName}}
  Email: {{.Email}}

  {{.BaseURL}}/activate/{{.Token}}

This URL will expire in 24 hours. If you don't want an account to be setup, feel
free to simply ignore this email.
{{end}}

{{define "lost_password_html"}}
<p>
Dear {{.FirstName}} {{.LastName}},
</p>

<p>
We received a request to reset the password for your account, if this request
was initiated by you, then you can go ahead and reset your password at the
link below. This link will expire in 24 hours.
</p>

<p>
<b>Name:</b> {{.FirstName}} {{.LastName}}<br/>
<b>Email:</b> {{.Email}}
<p>

<p>
<a href="{{.BaseURL}}/reset/{{.Token}}">{{.BaseURL}}/reset/{{.Token}}</a>
</p>

<p>
If you did not initiate this password reset request, no action is required,
simply ignore this email.
</p>
{{end}}

{{define "lost_password_text"}}
Dear {{.FirstName}} {{.LastName}}

We received a request to reset the password for your account, if this request
was initiated by you, then you can go ahead and reset your password at the
link below. This link will expire in 24 hours.

  Name: {{.FirstName}} {{.LastName}}
  Email: {{.Email}}

  {{.BaseURL}}/reset/{{.Token}}

If you did not initiate this password reset request, no action is required,
simply ignore this email.
{{end}}
`
