package security

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/uuid"
	"github.com/zaddok/log"
	"google.golang.org/api/iterator"
)

type GaeAccessManager struct {
	client           *datastore.Client
	ctx              context.Context
	log              log.Log
	setting          Setting
	throttle         Throttle
	picklistStore    PicklistStore
	template         *template.Template
	roleTypes        []*GaeRoleType
	virtualHostSetup VirtualHostSetup // setup function pointer
}

func (am *GaeAccessManager) GetCustomRoleTypes() []RoleType {
	r := make([]RoleType, len(am.roleTypes), len(am.roleTypes))
	for i, rt := range am.roleTypes {
		r[i] = rt
	}
	return r
}

func (am *GaeAccessManager) SetVirtualHostSetupHandler(fn VirtualHostSetup) {
	am.virtualHostSetup = fn
}

func (am *GaeAccessManager) RunVirtualHostSetupHandler(site string) {
	if am.virtualHostSetup != nil {
		am.virtualHostSetup(site, am)
	}
}

func (am *GaeAccessManager) AddCustomRoleType(uid, name, description string) {
	if uid == "" {
		return
	}
	am.roleTypes = append(am.roleTypes, &GaeRoleType{Uid: uid, Name: name, Description: description})
}

type GaeRequestToken struct {
	Uuid       string
	PersonUuid string
	Type       string
	IP         string
	Expiry     int64
	Data       string
}

type GaePerson struct {
	Uuid         string
	FirstName    string
	LastName     string
	Email        string
	Password     *string
	Created      *time.Time
	LastSignin   *time.Time
	LastSigninIP string
	NameKey      string
	Roles        string
	Site         string          `datastore:"-"`
	RoleMap      map[string]bool `datastore:"-"`
}

func (p *GaePerson) GetUuid() string {
	return p.Uuid
}

func (p *GaePerson) GetFirstName() string {
	return p.FirstName
}

func (p *GaePerson) GetLastName() string {
	return p.LastName
}

func (p *GaePerson) GetDisplayName() string {
	return p.FirstName + " " + p.LastName
}

func (p *GaePerson) GetSite() string {
	return p.Site
}

func (p *GaePerson) GetEmail() string {
	return p.Email
}

func (p *GaePerson) GetRoles() []string {
	return strings.FieldsFunc(p.Roles, func(c rune) bool { return c == ':' })
}

func (p *GaePerson) HasRole(uid string) bool {
	if p.RoleMap == nil {
		p.RoleMap = make(map[string]bool)
		for _, v := range strings.FieldsFunc(p.Roles, func(c rune) bool { return c == ':' }) {
			p.RoleMap[v] = true
		}
	}

	_, found := p.RoleMap[uid]
	return found
}

type GaeSession struct {
	PersonUUID    string
	FirstName     string
	LastName      string
	Email         string
	Created       int64
	Expiry        int64
	Authenticated bool
	Token         string `datastore:"-"`
	CSRF          string
	Site          string `datastore:"-"`
	Roles         string
	RoleMap       map[string]bool `datastore:"-"`
}

func (s *GaeSession) GetPersonUuid() string {
	return s.PersonUUID
}

func (s *GaeSession) GetToken() string {
	return s.Token
}

func (s *GaeSession) GetCSRF() string {
	return s.CSRF
}

func (s *GaeSession) GetSite() string {
	return s.Site
}

func (s *GaeSession) GetFirstName() string {
	return s.FirstName
}

func (s *GaeSession) GetLastName() string {
	return s.LastName
}

func (s *GaeSession) GetDisplayName() string {
	return s.FirstName + " " + s.LastName
}

func (s *GaeSession) GetEmail() string {
	return s.Email
}

func (s *GaeSession) IsAuthenticated() bool {
	return s.Authenticated
}

func (s *GaeSession) HasRole(uid string) bool {
	_, found := s.RoleMap[uid]
	return found
}

type GaeRoleType struct {
	Uid         string
	Name        string
	Description string
}

func (r *GaeRoleType) GetUid() string {
	return r.Uid
}

func (r *GaeRoleType) GetName() string {
	return r.Name
}

func (r *GaeRoleType) GetDescription() string {
	return r.Description
}

func NewGaeAccessManager(projectId string, log log.Log) (AccessManager, error, *datastore.Client, context.Context) {

	settings, client, ctx := NewGaeSetting(projectId)
	throttle := NewGaeThrottle(settings, client, ctx)

	t := template.New("api")
	var err error

	if t, err = t.Parse(emailHtmlTemplates); err != nil {
		log.Error("Email Template Problem: %s", err)
		return nil, err, nil, nil
	}

	picklistStore := NewGaePicklistStore(projectId, client, ctx)

	return &GaeAccessManager{
		client:        client,
		ctx:           ctx,
		log:           log,
		setting:       settings,
		throttle:      throttle,
		picklistStore: picklistStore,
		template:      t,
	}, nil, client, ctx
}

func (c *GaeAccessManager) Setting() Setting {
	return c.setting
}

func (c *GaeAccessManager) PicklistStore() PicklistStore {
	return c.picklistStore
}

func (c *GaeAccessManager) Log() log.Log {
	return c.log
}

func (a *GaeAccessManager) Signup(site, first_name, last_name, email, password, ip string) (*[]string, string, error) {
	var results []string

	email = strings.ToLower(strings.TrimSpace(email))

	// Check email does not already exist
	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email = ", email).Limit(1)
	_, err := a.client.GetAll(a.ctx, q, &items)
	if err != nil {
		return nil, "", err
	}
	if len(items) > 0 {
		results = append(results, "This email address already belongs to a valid user.")
	}
	passwordCheck := PasswordStrength(password)
	if len(passwordCheck) > 0 {
		results = append(results, passwordCheck...)
	}

	if strings.ToLower(a.setting.GetWithDefault(site, "self.signup", "no")) == "no" {
		results = append(results, "Self registration is not allowed at this time.")
		return &results, "", errors.New(results[0])
	}

	smtpHostname := a.setting.GetWithDefault(site, "smtp.hostname", "")
	smtpPassword := a.setting.GetWithDefault(site, "smtp.password", "")
	smtpPort := a.setting.GetWithDefault(site, "smtp.port", "")
	smtpUser := a.setting.GetWithDefault(site, "smtp.user", "")
	supportName := a.setting.GetWithDefault(site, "support_team.name", "")
	supportEmail := a.setting.GetWithDefault(site, "support_team.email", "")
	baseUrl := a.setting.GetWithDefault(site, "base.url", "")

	ui := &NewUserInfo{
		Site:      site,
		FirstName: first_name,
		LastName:  last_name,
		Email:     email,
		Password:  HashPassword(password),
	}
	data, merr := json.Marshal(ui)

	if smtpHostname == "" {
		results = append(results, "Missing \"smtp.hostname\" host, setting, cant send message notification")
	}
	if smtpPort == "" {
		results = append(results, "Missing \"smtp.port\" setting, cant send message notification")
	}
	if supportName == "" {
		results = append(results, "Missing \"support_team.name\" setting, cant send message notification")
	}
	if supportEmail == "" {
		results = append(results, "Missing \"support_team.email\" setting, cant send message notification")
	}
	if merr != nil {
		results = append(results, "Internal server error. "+merr.Error())
		a.log.Info("%s doSignup() mashal error: %v", ip, merr.Error())
	}

	if len(results) > 0 {
		return &results, "", errors.New(results[0])
	}

	token, err := uuid.NewUUID()
	if err != nil {
		return nil, "", err
	}
	a.log.Info("%s Sign up confirmation token for \"%s\" is \"%s\"", ip, email, token.String())

	//TODO: expiry time set to actual desired expiry time

	k := datastore.NameKey("RequestToken", token.String(), nil)
	k.Namespace = site
	i := GaeRequestToken{Uuid: token.String(), PersonUuid: token.String(), Type: `signup_confirmation`, IP: ip, Expiry: time.Now().Unix(), Data: string(data)}
	if _, err := a.client.Put(a.ctx, k, &i); err != nil {
		return nil, "", err
	}

	type Page struct {
		Site      string
		BaseURL   string
		Uuid      string
		FirstName string
		LastName  string
		Email     string
		Token     string
	}
	p := &Page{}
	p.Site = site
	p.Email = email
	p.Uuid = token.String()
	p.LastName = last_name
	p.FirstName = first_name
	p.Token = p.Uuid
	if baseUrl == "" {
		p.BaseURL = "http://" + site
	} else {
		p.BaseURL = baseUrl
	}

	var w bytes.Buffer
	boundary := RandomString(20)
	w.Write([]byte(fmt.Sprintf("Subject: Signup confirmation\r\n")))
	w.Write([]byte(fmt.Sprintf("From: %s <%s>\r\n", supportName, supportEmail)))
	w.Write([]byte(fmt.Sprintf("To: %s\r\n", email)))
	w.Write([]byte("Content-transfer-encoding: 8BIT\r\n"))
	w.Write([]byte(fmt.Sprintf("Content-type: multipart/alternative; charset=UTF-8; boundary=%s\r\n", boundary)))
	w.Write([]byte("MIME-version: 1.0\r\n\r\n"))
	w.Write([]byte(fmt.Sprintf("--%s\r\n", boundary)))
	w.Write([]byte("Content-Type: text/plain; charset=utf-8; format=flowed\r\n"))
	w.Write([]byte("Content-Transfer-Encoding: 8bit\r\n"))
	w.Write([]byte("Content-Disposition: inline\r\n"))
	err = a.template.ExecuteTemplate(&w, "signup_confirmation_text", p)
	if err != nil {
		results = append(results, fmt.Sprintf("Error rendering template \"signup_confirmation_text\": %v", err))
		return &results, "", errors.New(results[0])
	}
	w.Write([]byte(fmt.Sprintf("\r\n--%s\r\n", boundary)))
	w.Write([]byte("Content-Transfer-Encoding: 8bit\r\n"))
	w.Write([]byte("Content-Type: text/html; charset=utf-8\r\n"))
	w.Write([]byte("Content-Transfer-Encoding: base64\r\n"))
	w.Write([]byte("Content-Disposition: inline\r\n\r\n"))
	var h bytes.Buffer
	err = a.template.ExecuteTemplate(&w, "signup_confirmation_html", p)
	if err != nil {
		results = append(results, fmt.Sprintf("Error rendering template \"signup_confirmation_html\": %v", err))
		return &results, "", errors.New(results[0])
	}
	w.Write([]byte(base64.StdEncoding.EncodeToString(h.Bytes())))
	w.Write([]byte(fmt.Sprintf("\r\n--%s--\r\n", boundary)))
	to := []string{email}
	msg := w.Bytes()
	var auth smtp.Auth
	if smtpUser != "" && smtpPassword != "" {
		auth = smtp.PlainAuth("", smtpUser, smtpPassword, smtpHostname)
	}
	err = smtp.SendMail(fmt.Sprintf("%s:%s", smtpHostname, smtpPort), auth, supportEmail, to, msg)
	if err != nil {
		a.log.Error("%s Send signup confirmation mail failed: %v", ip, err)
		results = append(results, "Sending your signup confirmation mail failed. Please retry shortly.")
		return &results, "", errors.New(results[0])
	} else {
		a.log.Info("%s Sent signup confirmation mail to: %s", ip, email)
	}

	return nil, token.String(), nil
}

func (a *GaeAccessManager) ForgotPasswordRequest(site, email, ip string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	syslog := NewGaeSyslogBundle(site, a.client, a.ctx)
	defer syslog.Put()

	syslog.Add(`auth`, ip, `fine`, fmt.Sprintf("ForgotPasswordRequest '%s'", email))

	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email = ", email).Limit(1)
	_, err := a.client.GetAll(a.ctx, q, &items)
	if err != nil {
		a.Log().Error("ForgotPasswordRequest() Person lookup Error: %v", err)
		return "", err
	}
	if len(items) == 0 {
		a.Log().Info("Forgot Password Request ignored for unknown email address: " + email)
		syslog.Add(`auth`, ip, `fine`, fmt.Sprintf("ForgotPassword with unknown email address: %s", email))
		return "", nil
	}
	if items[0].Password == nil || *items[0].Password == "" {
		a.Log().Info("Forgot Password Request ignored for account with an empty password field. Email: " + email)
		syslog.Add(`auth`, ip, `fine`, fmt.Sprintf("ForgotPassword with an empty password.  Email address: %s", email))
		return "", nil
	}

	token, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	smtpHostname := a.setting.GetWithDefault(site, "smtp.hostname", "")
	smtpPassword := a.setting.GetWithDefault(site, "smtp.password", "")
	smtpPort := a.setting.GetWithDefault(site, "smtp.port", "")
	smtpUser := a.setting.GetWithDefault(site, "smtp.user", "")
	supportName := a.setting.GetWithDefault(site, "support_team.name", "")
	supportEmail := a.setting.GetWithDefault(site, "support_team.email", "")
	baseUrl := a.setting.GetWithDefault(site, "base.url", "")

	type Page struct {
		Site      string
		BaseURL   string
		Uuid      string
		FirstName string
		LastName  string
		Email     string
		Token     string
	}
	p := &Page{}
	p.Site = site
	p.Email = email
	p.Uuid = token.String()
	p.Token = token.String()
	p.FirstName = items[0].FirstName
	p.LastName = items[0].LastName
	if baseUrl == "" {
		p.BaseURL = "http://" + site
	} else {
		p.BaseURL = baseUrl
	}

	k := datastore.NameKey("RequestToken", token.String(), nil)
	k.Namespace = site
	i := GaeRequestToken{Uuid: token.String(), PersonUuid: items[0].Uuid, Type: `password_reset`, IP: ip, Expiry: time.Now().Unix(), Data: ""}
	if _, err := a.client.Put(a.ctx, k, &i); err != nil {
		return "Unable to process password reset request. Please try again.", err
	}

	var w bytes.Buffer
	boundary := RandomString(20)
	w.Write([]byte(fmt.Sprintf("Subject: Lost password request\r\n")))
	w.Write([]byte(fmt.Sprintf("From: %s <%s>\r\n", supportName, supportEmail)))
	w.Write([]byte(fmt.Sprintf("To: %s\r\n", email)))
	w.Write([]byte("Content-transfer-encoding: 8BIT\r\n"))
	w.Write([]byte(fmt.Sprintf("Content-type: multipart/alternative; charset=UTF-8; boundary=%s\r\n", boundary)))
	w.Write([]byte("MIME-version: 1.0\r\n\r\n"))
	w.Write([]byte(fmt.Sprintf("--%s\r\n", boundary)))
	w.Write([]byte("Content-Type: text/plain; charset=utf-8; format=flowed\r\n"))
	w.Write([]byte("Content-Transfer-Encoding: 8bit\r\n"))
	w.Write([]byte("Content-Disposition: inline\r\n"))
	err = a.template.ExecuteTemplate(&w, "lost_password_text", p)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error rendering template \"lost_password_text\": %v", err))
	}
	w.Write([]byte(fmt.Sprintf("\r\n--%s\r\n", boundary)))
	w.Write([]byte("Content-Transfer-Encoding: 8bit\r\n"))
	w.Write([]byte("Content-Type: text/html; charset=utf-8\r\n"))
	w.Write([]byte("Content-Transfer-Encoding: base64\r\n"))
	w.Write([]byte("Content-Disposition: inline\r\n\r\n"))
	var h bytes.Buffer
	err = a.template.ExecuteTemplate(&w, "lost_password_html", p)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error rendering template \"lost_password_html\": %v", err))
	}
	w.Write([]byte(base64.StdEncoding.EncodeToString(h.Bytes())))
	w.Write([]byte(fmt.Sprintf("\r\n--%s--\r\n", boundary)))
	to := []string{email}
	msg := w.Bytes()
	var auth smtp.Auth
	if smtpUser != "" && smtpPassword != "" {
		auth = smtp.PlainAuth("", smtpUser, smtpPassword, smtpHostname)
	}
	err = smtp.SendMail(fmt.Sprintf("%s:%s", smtpHostname, smtpPort), auth, supportEmail, to, msg)
	if err != nil {
		a.log.Error("%s Sending lost password email failed: %v", ip, err)
		return "", err
	}

	a.log.Info("%s Sent signup confirmation mail to: %s", ip, email)
	return token.String(), nil
}

func (g *GaeAccessManager) Authenticate(site, email, password, ip string) (Session, string, error) {
	if email == "" {
		return g.GuestSession(site), "Invalid email address or password.", nil
	}

	syslog := NewGaeSyslogBundle(site, g.client, g.ctx)
	defer syslog.Put()
	syslog.Add(`auth`, ip, `debug`, fmt.Sprintf("Authentication attempt for '%s'", email))

	email = strings.ToLower(strings.TrimSpace(email))
	if throttled, _ := g.throttle.IsThrottled(email); throttled {
		syslog.Add(`auth`, ip, `info`, fmt.Sprintf("Authentication for '%s' blocked by throttle", email))
		return g.GuestSession(site), "Repeated signin failures were detected from your location, please wait a few minutes and try again.", nil
	}

	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email = ", email).Limit(1)
	_, err := g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		g.Log().Error("Authenticate() Person lookup Error: %v", err)
		return g.GuestSession(site), "", err
	}
	if len(items) > 0 {
		if items[0].Password == nil || *items[0].Password == "" {
			g.throttle.Increment(email)
			syslog.Add(`auth`, ip, `warn`, fmt.Sprintf("Authentication for '%s' blocked. Account has no password.", email))
			return g.GuestSession(site), "Invalid email address or password.", nil
		}

		if !VerifyPassword(*items[0].Password, password) {
			g.throttle.Increment(email)
			syslog.Add(`auth`, ip, `notice`, fmt.Sprintf("Authentication for '%s' failed. Incorrect password.", email))
			return g.GuestSession(site), "Invalid email address or password.", nil
		}

		now := time.Now()
		items[0].LastSignin = &now
		items[0].LastSigninIP = ip
		k := datastore.NameKey("Person", items[0].Uuid, nil)
		k.Namespace = site
		if _, err := g.client.Put(g.ctx, k, &items[0]); err != nil {
			g.Log().Error("Authenticate() Person update Error: %v", err)
			return g.GuestSession(site), "", err
		}

		token, err2 := g.createSession(site, items[0].Uuid, items[0].FirstName, items[0].LastName, items[0].Email, items[0].Roles, ip)
		if err2 != nil {
			g.Log().Error("Authenticate() Session creation error: %v", err2)
			return g.GuestSession(site), "", err2
		}
		syslog.Add(`auth`, ip, `info`, fmt.Sprintf("Authentication success for '%s'", email))

		session := &GaeSession{
			PersonUUID:    items[0].Uuid,
			Token:         token,
			Site:          site,
			FirstName:     items[0].FirstName,
			LastName:      items[0].LastName,
			Email:         items[0].Email,
			Roles:         items[0].Roles,
			CSRF:          RandomString(8),
			Authenticated: true,
			RoleMap:       make(map[string]bool),
		}
		for _, v := range strings.FieldsFunc(session.Roles, func(c rune) bool { return c == ':' }) {
			session.RoleMap[v] = true
		}

		return session, "", nil
	}

	// User lookup failed
	if throttled, _ := g.throttle.IsThrottled(ip); throttled {
		// An invalid email address was entered. If this occurs too many times, stop reporting
		// back the normal "Invalid email address or password" message prevent the signin form
		// revealing to a bot that this email address/password combination is invalid.
		syslog.Add(`auth`, ip, `debug`, fmt.Sprintf("Authentication for '%s' blocked by throttle", email))
		return g.GuestSession(site), "Repeated signin failures were detected, please wait a few minutes and try again.", nil
	}

	g.throttle.Increment(ip)
	syslog.Add(`auth`, ip, `info`, fmt.Sprintf("Authentication for '%s' failed. Email address not registered on this site.", email))
	return g.GuestSession(site), "Invalid email address or password.", nil
}
func (a *GaeAccessManager) GetRecentSystemLog(requestor Session) ([]SystemLog, error) {
	var items []SystemLog

	if !requestor.HasRole("s1") {
		return items, errors.New("Permission denied.")
	}

	q := datastore.NewQuery("SystemLog").Namespace(requestor.GetSite()).Order("-Recorded").Limit(200)
	it := a.client.Run(a.ctx, q)
	for {
		e := new(GaeSystemLog)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		items = append(items, e)
	}

	return items[:], nil
}

func (am *GaeAccessManager) GetRecentLogCollections(requestor Session) ([]LogCollection, error) {
	var items []LogCollection

	if !requestor.HasRole("s1") {
		return items, errors.New("Permission denied.")
	}

	q := datastore.NewQuery("LogCollection").Namespace(requestor.GetSite()).Order("-Began").Limit(200)
	it := am.client.Run(am.ctx, q)
	for {
		e := new(GaeLogCollection)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		items = append(items, e)
	}

	return items[:], nil
}

func (am *GaeAccessManager) GetEntityChangeLog(uuid string, requestor Session) ([]EntityAuditLogCollection, error) {
	var items []EntityAuditLogCollection

	if !requestor.HasRole("s1") {
		return nil, errors.New("Permission denied.")
	}

	pkey := datastore.NameKey("EntityChange", uuid, nil)
	pkey.Namespace = requestor.GetSite()

	q := datastore.NewQuery("EntityChange").Namespace(requestor.GetSite()).Ancestor(pkey).Limit(500)
	it := am.client.Run(am.ctx, q)
	for {
		e := new(GaeEntityAuditLogCollection)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		items = append(items, e)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[j].GetDate().Before(items[i].GetDate())
	})

	return items[:], nil
}

func (am *GaeAccessManager) AddEntityChangeLog(ec EntityAuditLogCollection, requestor Session) error {
	var e *GaeEntityAuditLogCollection = ec.(*GaeEntityAuditLogCollection)

	if e.EntityUuid == "" {
		return errors.New("Invalid entity uuid.")
	}

	pkey := datastore.NameKey("EntityChange", e.EntityUuid, nil)
	pkey.Namespace = requestor.GetSite()
	key := datastore.IncompleteKey("EntityChange", pkey)
	key.Namespace = requestor.GetSite()

	if _, err := am.client.Put(am.ctx, key, e); err != nil {
		return err
	}

	return nil
}

func (am *GaeAccessManager) GetLogCollection(uuid string, requestor Session) ([]LogEntry, error) {
	var items []LogEntry

	if !requestor.HasRole("s1") {
		return items, errors.New("Permission denied.")
	}

	q := datastore.NewQuery("LogEntry").Namespace(requestor.GetSite()).Filter("LogUuid =", uuid).Order("Recorded").Limit(10000)
	it := am.client.Run(am.ctx, q)
	for {
		e := new(GaeLogEntry)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		items = append(items, e)
	}

	return items[:], nil
}

func (am *GaeAccessManager) GetPerson(uuid string, requestor Session) (Person, error) {
	if !requestor.HasRole("s1") && requestor.GetPersonUuid() != uuid {
		return nil, errors.New("Permission denied.")
	}

	k := datastore.NameKey("Person", uuid, nil)
	k.Namespace = requestor.GetSite()
	i := new(GaePerson)
	err := am.client.Get(am.ctx, k, i)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return i, nil
}

func (am *GaeAccessManager) GetPeople(requestor Session) ([]Person, error) {
	var items []Person

	if !requestor.HasRole("s1") {
		return items, errors.New("Permission denied.")
	}

	q := datastore.NewQuery("Person").Namespace(requestor.GetSite()).Limit(2000)
	it := am.client.Run(am.ctx, q)
	for {
		e := new(GaePerson)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		e.Site = requestor.GetSite()
		items = append(items, e)
	}

	return items[:], nil
}

func (am *GaeAccessManager) UpdatePerson(uuid, firstName, lastName, email, roles, password string, updator Session) error {
	if !updator.HasRole("s3") && updator.GetPersonUuid() != uuid {
		return errors.New("Permission denied.")
	}

	if password != "" {
		passwordCheck := PasswordStrength(password)
		if len(passwordCheck) > 0 {
			return errors.New("Password is insecure. " + passwordCheck[0])
		}
	}

	k := datastore.NameKey("Person", uuid, nil)
	k.Namespace = updator.GetSite()
	i := new(GaePerson)
	err := am.client.Get(am.ctx, k, i)
	if err == datastore.ErrNoSuchEntity {
		return errors.New("Person not found.")
	} else if err != nil {
		return err
	}

	// Normal users may not update their own system roles
	if !updator.HasRole("s3") && updator.GetPersonUuid() == uuid {
		if roles != i.Roles {
			return errors.New("Permission denied.")
		}
	}

	bulk := &GaeEntityAuditLogCollection{}
	bulk.SetEntityUuidPersonUuid(uuid, updator.GetPersonUuid(), updator.GetDisplayName())
	if firstName != i.FirstName {
		bulk.AddItem("FirstName", i.FirstName, firstName)
		i.FirstName = firstName
	}
	if lastName != i.LastName {
		bulk.AddItem("LastName", i.LastName, lastName)
		i.LastName = lastName
	}
	if email != i.Email {
		bulk.AddItem("Email", i.Email, email)
		i.Email = email
	}
	if roles != i.Roles {
		bulk.AddItem("Roles", i.Roles, roles)
		i.Roles = roles
	}
	if len(password) > 0 {
		bulk.AddItem("Password", "", "")
		i.Password = HashPassword(password)
	}
	if bulk.HasUpdates() {
		if err = am.AddEntityChangeLog(bulk, updator); err != nil {
			am.Log().Error("UpdatePerson() failed persisting changelog. Error: %v", err)
			return err
		}
		if _, err := am.client.Put(am.ctx, k, i); err != nil {
			am.Log().Error("UpdatePerson() failed. Error: %v", err)
			return err
		}
	}
	return nil
}

func (am *GaeAccessManager) DeletePerson(uuid string, updator Session) error {
	if !updator.HasRole("s3") {
		return errors.New("Permission denied.")
	}

	return errors.New("unimplemented")
}

func (am *GaeAccessManager) SearchPeople(keyword string, requestor Session) ([]Person, error) {
	if !requestor.HasRole("s1") {
		return []Person{}, errors.New("Permission denied.")
	}

	return am.GetPeople(requestor)
}

func (g *GaeAccessManager) GetPersonByFirstNameLastName(site, firstname, lastname string, requestor Session) (Person, error) {
	if requestor != nil && !requestor.HasRole("s1") {
		return nil, errors.New("Permission denied.")
	}

	firstname = strings.TrimSpace(firstname)
	lastname = strings.TrimSpace(lastname)
	namekey := strings.ToLower(firstname + "|" + lastname)

	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("NameKey =", namekey).Limit(2)
	_, err := g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) > 1 {
		return nil, errors.New("Multiple accounts have this first and last name")
	}

	items[0].Site = site
	return &items[0], nil
}

// Request the session information associated the site hostname and cookie in the web request
func (g *GaeAccessManager) GetSystemSession(site, firstname, lastname string) (Session, error) {
	now := time.Now()
	firstname = strings.TrimSpace(firstname)
	lastname = strings.TrimSpace(lastname)

	person, err := g.GetPersonByFirstNameLastName(site, firstname, lastname, nil)
	if err != nil {
		return nil, err
	}
	puuid := ""
	if person != nil {
		puuid = person.GetUuid()
	}
	if person == nil {

		uuid, err := uuid.NewUUID()
		if err != nil {
			return nil, err
		}
		person := &GaePerson{
			Uuid:      uuid.String(),
			Site:      site,
			FirstName: firstname,
			LastName:  lastname,
			Roles:     "s1:s2:s3:s4",
			NameKey:   strings.ToLower(firstname + "|" + lastname),
			Created:   &now,
		}
		k := datastore.NameKey("Person", uuid.String(), nil)
		k.Namespace = site
		if _, err := g.client.Put(g.ctx, k, person); err != nil {
			g.Log().Error("GetSystemSession() Person creation failed. Error: %v", err)
			return nil, err
		}
		puuid = uuid.String()
	}

	token := RandomString(32)
	session := &GaeSession{
		Site:          site,
		PersonUUID:    puuid,
		Token:         token,
		FirstName:     firstname,
		LastName:      lastname,
		Authenticated: true,
		CSRF:          RandomString(8),
		Roles:         "s1:s2:s3:s4",
		RoleMap:       make(map[string]bool),
	}
	for _, v := range strings.FieldsFunc(session.Roles, func(c rune) bool { return c == ':' }) {
		session.RoleMap[v] = true
	}

	return session, nil
}

// Request the session information associated the site hostname and cookie in the web request
func (g *GaeAccessManager) Session(site, cookie string) (Session, error) {
	if len(cookie) > 0 {
		k := datastore.NameKey("Session", cookie, nil)
		k.Namespace = site
		i := new(GaeSession)
		err := g.client.Get(g.ctx, k, i)
		if err == datastore.ErrNoSuchEntity || i.Expiry < time.Now().Unix() {
			return g.GuestSession(site), nil
		} else if err != nil {
			return g.GuestSession(site), err
		}

		session := &GaeSession{
			Site:          site,
			PersonUUID:    i.PersonUUID,
			Token:         cookie,
			FirstName:     i.FirstName,
			LastName:      i.LastName,
			Email:         i.Email,
			Authenticated: true,
			Roles:         i.Roles,
			CSRF:          i.CSRF,
			RoleMap:       make(map[string]bool),
		}
		for _, v := range strings.FieldsFunc(session.Roles, func(c rune) bool { return c == ':' }) {
			session.RoleMap[v] = true
		}

		expiry := g.setting.GetWithDefault(site, "session.expiry", "")
		if expiry == "" {
			expiry = "3600"
			g.log.Warning("System setting \"session.expiry\" not set, defaulting to 1 hour.")
		}
		e, err := strconv.ParseInt(expiry, 10, 64)
		if err != nil {
			e = 3600
			g.log.Warning("System setting \"session.expiry\" is not a valid number, defaulting to 1 hour.")
		}

		// Check this user session hasn't hit its maximum hard limit
		maxAge := g.setting.GetInt(site, "session.max_age", 2592000)
		newExpiry := time.Now().Add(time.Second * time.Duration(e)).Unix()
		if i.Created+int64(maxAge) < newExpiry {
			g.log.Warning("User session hit \"session.max_age\".")
			return g.GuestSession(site), nil
		}

		// So "expires" is still in the future... Update the session expiry in the database
		if newExpiry-i.Expiry > 30 {
			//g.Log().Debug("updating expiry new:  %d old: %d", newExpiry, i.Expiry)

			i.Expiry = newExpiry
			if _, err := g.client.Put(g.ctx, k, i); err != nil {
				g.Log().Error("Session() Session expiry update failed: %v", err)
				return session, nil
			}
		} else {
			// Session expiry field will only be updated every 30 seconds
			// No need to hit the databbase with a session update upon every single page load
		}

		return session, nil
	}

	g.log.Debug("Session() no valid cookie")

	return g.GuestSession(site), nil
}

func (g *GaeAccessManager) GuestSession(site string) Session {
	return &GaeSession{
		Token:         "",
		Site:          site,
		FirstName:     "",
		LastName:      "",
		Authenticated: false,
		Roles:         "",
		CSRF:          "",
		RoleMap:       make(map[string]bool),
	}
}

func (g *GaeAccessManager) Invalidate(site, cookie string) (Session, error) {
	session, err := g.Session(site, cookie)

	// Delete session information

	return session, err
}

// Password must already be hashed
func (g *GaeAccessManager) AddPerson(site, firstName, lastName, email, roles string, password *string, ip string, requestor Session) (string, error) {
	if requestor != nil && !requestor.HasRole("s1") {
		return "", errors.New("Permission denied.")
	}

	if password != nil {
		passwordCheck := PasswordStrength(*password)
		if len(passwordCheck) > 0 {
			return "", errors.New("Password is insecure. " + passwordCheck[0])
		}
	}

	syslog := NewGaeSyslogBundle(site, g.client, g.ctx)
	defer syslog.Put()

	firstName = strings.TrimSpace(firstName)
	lastName = strings.TrimSpace(lastName)
	email = strings.ToLower(strings.TrimSpace(email))

	uuid, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	si := &GaePerson{
		Uuid:      uuid.String(),
		Site:      site,
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		Roles:     roles,
		Password:  password,
		NameKey:   strings.ToLower(firstName + "|" + lastName),
		Created:   &now,
	}

	if requestor == nil {
		requestor = &GaeSession{
			PersonUUID: si.Uuid,
			Site:       site,
			FirstName:  firstName,
			LastName:   lastName,
			Email:      email,
			Roles:      roles,
		}
	}

	bulk := &GaeEntityAuditLogCollection{}
	bulk.SetEntityUuidPersonUuid(uuid.String(), requestor.GetPersonUuid(), requestor.GetDisplayName())

	if firstName != "" {
		bulk.AddItem("FirstName", "", firstName)
	}
	if lastName != "" {
		bulk.AddItem("LastName", "", lastName)
	}
	if email != "" {
		bulk.AddItem("Email", "", email)
	}
	if roles != "" {
		bulk.AddItem("Roles", "", roles)
	}
	if err = g.AddEntityChangeLog(bulk, requestor); err != nil {
		g.Log().Error("AddPerson() failed persisting changelog. Error: %v", err)
		return "", err
	}

	k := datastore.NameKey("Person", uuid.String(), nil)
	k.Namespace = site
	if _, err := g.client.Put(g.ctx, k, si); err != nil {
		g.Log().Error("AddPerson() Person storage failed. Error: %v", err)
		return "", err
	}
	syslog.Add(`auth`, ip, `notice`, fmt.Sprintf("New user account created '%s','%s','%s'", firstName, lastName, email))

	return uuid.String(), nil
}

func (g *GaeAccessManager) ActivateSignup(site, token, ip string) (string, string, error) {
	syslog := NewGaeSyslogBundle(site, g.client, g.ctx)
	defer syslog.Put()

	// Check the token is a valid uuid
	_, err := uuid.Parse(token)
	if err != nil {
		g.Log().Error("ActivateSignup() called with invalid uuid: " + err.Error())
		return "", "Invalid account activation token", nil
	}

	// Lookup the request token for the account creation request details
	maxAge := g.setting.GetInt(site, "activation_token.max_age", 2592000)
	k := datastore.NameKey("RequestToken", token, nil)
	k.Namespace = site
	si := new(GaeRequestToken)
	err = g.client.Get(g.ctx, k, si)
	if err == datastore.ErrNoSuchEntity {
		g.Log().Error("ActivateSignup() called with uuid not in the datastore: " + err.Error())
		return "", "Invalid activation token", nil
	} else if err != nil {
		g.Log().Error("ActivateSignup() failure: " + err.Error())
		return "", "Activation service failed, please try again.", err
	} else if si.Expiry+int64(maxAge) < time.Now().Unix() {
		g.Log().Error("ActivateSignup() called with expired uuid: %d < %d ", si.Expiry, time.Now().Unix())
		return "", "Invalid activation token", nil
	}
	i := &NewUserInfo{}
	json.Unmarshal([]byte(si.Data), i)

	// Do one last final double check an account does not exist with this email address
	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email = ", i.Email).Limit(1)
	_, err = g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		g.Log().Error("ActivateSignup() email lookup failure: " + err.Error())
		return "", "Activation service failed, please try again.", err
	}
	if len(items) > 0 {
		g.Log().Error("ActivateSignup() Email address already exists: %v", err)
		return "", "Can't complete account activation, this email address has recently been activated by a different person.", nil
	}

	// NewUserInfo doesnt carry roles, should it?
	uuid, aerr := g.AddPerson(site, i.FirstName, i.LastName, i.Email, "", i.Password, ip, nil)
	if aerr != nil {
		g.Log().Error("addPerson() failure: " + aerr.Error())
		return "", "", aerr
	}
	syslog.Add(`auth`, ip, `notice`, fmt.Sprintf("New user account activated '%s','%s','%s'", i.FirstName, i.LastName, i.Email))

	// NewUserInfo doesn't permit default/initial roles. Should it?
	token, err2 := g.createSession(site, uuid, i.FirstName, i.LastName, i.Email, "", ip)
	if err2 == nil {
		return token, "", nil
	}

	g.Log().Error("addPerson() createSession() failure: " + err2.Error())
	return "", "", err2
}

func (g *GaeAccessManager) ResetPassword(site, token, password, ip string) (bool, string, error) {
	// Check the token is a valid uuid
	_, err := uuid.Parse(token)
	if err != nil {
		g.Log().Error("ResetPassword() called with invalid uuid: " + err.Error())
		return false, "Invalid password reset token", nil
	}

	// Lookup the request token for the forgot password request details
	maxAge := g.setting.GetInt(site, "password_reset_token.max_age", 93600)
	k := datastore.NameKey("RequestToken", token, nil)
	k.Namespace = site
	si := new(GaeRequestToken)
	err = g.client.Get(g.ctx, k, si)
	if err == datastore.ErrNoSuchEntity {
		g.Log().Error("ResetPassword() called with uuid not in the datastore: " + err.Error())
		return false, "Invalid reset password token", nil
	} else if err != nil {
		g.Log().Error("ResetPassword() failure: " + err.Error())
		return false, "Password reset service failed, please try again.", err
	} else if si.Expiry+int64(maxAge) < time.Now().Unix() {
		g.Log().Error("ResetPassword() called with expired uuid: %d < %d ", si.Expiry, time.Now().Unix())
		return false, "This password reset link has expired.", nil
	}

	// Do one last final double check an account does not exist with this email address
	var person GaePerson
	k = datastore.NameKey("Person", si.PersonUuid, nil)
	k.Namespace = site
	err = g.client.Get(g.ctx, k, &person)
	if err == datastore.ErrNoSuchEntity {
		g.Log().Error("ResetPassword() person lookup by uuid failed: " + err.Error())
		return false, "Reset password service failed, please try again.", err
	} else if err != nil {
		g.Log().Error("ResetPassword() email lookup failure: " + err.Error())
		return false, "Reset password service failed, please try again.", err
	}
	person.Password = HashPassword(password)
	_, err = g.client.Put(g.ctx, k, &person)

	return true, "Your password has been reset", nil
}

func (g *GaeAccessManager) createSession(site, person, firstName, lastName, email, roles, ip string) (string, error) {
	personUuid, perr := uuid.Parse(person)
	if perr != nil {
		return "", perr
	}

	expiry := g.setting.GetWithDefault(site, "session.expiry", "")
	if expiry == "" {
		expiry = "3600"
		g.Log().Warning("System setting \"session.expiry\" not set, defaulting to 1 hour.")
	}
	e, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		e = 3600
		g.Log().Warning("System setting \"session.expiry\" is not a valid number, defaulting to 1 hour.")
	}

	token := RandomString(32)
	now := time.Now().Unix()
	expires := e + now

	if err != nil {
		return "", err
	}

	ri := &GaeSession{
		PersonUUID: personUuid.String(),
		Token:      token,
		FirstName:  firstName,
		LastName:   lastName,
		Email:      email,
		Created:    now,
		Expiry:     expires,
		Roles:      roles,
		RoleMap:    make(map[string]bool),
		CSRF:       RandomString(8),
	}
	for _, v := range strings.FieldsFunc(ri.Roles, func(c rune) bool { return c == ':' }) {
		ri.RoleMap[v] = true
	}
	k := datastore.NameKey("Session", token, nil)
	k.Namespace = site
	if _, err := g.client.Put(g.ctx, k, ri); err != nil {
		return "", err
	}

	tkn := token[0:len(token)/2] + "..."
	g.Log().Debug("Created session \"%s\" for user %v.", tkn, personUuid)

	return token, err
}

func (am *GaeAccessManager) WipeDatastore(namespace string) error {

	for {
		q := datastore.NewQuery("").Namespace(namespace).KeysOnly().Limit(20)
		keys, err := am.client.GetAll(am.ctx, q, nil)
		if err != nil {
			return err
		}

		err = am.client.DeleteMulti(am.ctx, keys)
		if err != nil {
			return err
		}
		for _, k := range keys {
			fmt.Printf("   key: %v\n", k)
		}

		if len(keys) == 0 {
			break
		}
		fmt.Printf("keys deleted: %d\n", len(keys))
	}

	return nil
}
