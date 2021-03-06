package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/bluele/gcache"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

type GaeAccessManager struct {
	client                    *datastore.Client
	ctx                       context.Context
	setting                   Setting
	throttle                  Throttle
	picklistStore             PicklistStore
	template                  *template.Template
	roleTypes                 []*GaeRoleType
	virtualHostSetup          VirtualHostSetup // setup function pointer
	notificationEventHandlers []NotificationEventHandler
	authenticationHandlers    []AuthenticationHandler
	preAuthenticationHandlers []PreAuthenticationHandler
	taskHandlers              map[string]TaskHandler
	connectorInfo             []*ConnectorInfo
	systemSessions            map[string]Session
	systemCache               gcache.Cache
	sessionCache              gcache.Cache
	ipCache                   gcache.Cache
	personCache               gcache.Cache
	projectId                 string
	locationId                string
	defaultLocale             *time.Location
}

func (am *GaeAccessManager) ProjectId() string {
	return am.projectId
}

func (am *GaeAccessManager) LocationId() string {
	return am.locationId
}

func (am *GaeAccessManager) DefaultLocale() *time.Location {
	return am.defaultLocale
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

func (am *GaeAccessManager) AvailableSites() []string {
	var sites []string

	q := datastore.NewQuery("__namespace__").KeysOnly()
	keys, err := am.client.GetAll(am.ctx, q, nil)
	if err != nil {
		fmt.Printf("Failed looking up available sites: %v\n", err)
	} else {
		for _, k := range keys {
			sites = append(sites, k.Name)
		}
	}
	fmt.Printf("Current Keyspaces: %s\n", strings.Join(sites, ", "))
	return sites
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
	uuid         string          `datastore:"Uuid,noindex"`
	firstName    string          `datastore:"FirstName"`
	lastName     string          `datastore:"LastName"`
	email        string          `datastore:"Email"`
	password     *string         `datastore:"Password,noindex"`
	created      *time.Time      `datastore:"Created,noindex"`
	lastSignin   *time.Time      `datastore:"LastSignin,noindex"`
	lastSigninIP string          `datastore:"LastSigninIP"`
	nameKey      string          `datastore:"NameKey"`
	roles        string          `datastore:"Roles,noindex"`
	site         string          `datastore:"-"`
	roleMap      map[string]bool `datastore:"-"`
}

func (p *GaePerson) Load(ps []datastore.Property) error {
	for _, i := range ps {
		switch i.Name {
		case "Uuid":
			p.uuid = i.Value.(string)
			break
		case "FirstName":
			p.firstName = i.Value.(string)
			break
		case "LastName":
			p.lastName = i.Value.(string)
			break
		case "Email":
			p.email = i.Value.(string)
			break
		case "LastSigninIP":
			p.lastSigninIP = i.Value.(string)
			break
		case "NameKey":
			p.nameKey = i.Value.(string)
			break
		case "Roles":
			p.roles = i.Value.(string)
			break
		case "Site":
			p.site = i.Value.(string)
			break
		case "Password":
			if i.Value != nil {
				v := i.Value.(string)
				p.password = &v
			}
			break
		case "Created":
			if i.Value != nil {
				t := i.Value.(time.Time)
				p.created = &t
			}
			break
		case "LastSignin":
			if i.Value != nil {
				t := i.Value.(time.Time)
				p.lastSignin = &t
			}
			break
		}
	}
	return nil
}

func (p *GaePerson) Save() ([]datastore.Property, error) {
	props := []datastore.Property{
		{
			Name:  "Uuid",
			Value: p.uuid,
		},
		{
			Name:  "FirstName",
			Value: p.firstName,
		},
		{
			Name:  "LastName",
			Value: p.lastName,
		},
		{
			Name:  "Email",
			Value: p.email,
		},
		{
			Name:  "LastSigninIP",
			Value: p.lastSigninIP,
		},
		{
			Name:  "NameKey",
			Value: p.nameKey,
		},
		{
			Name:  "Roles",
			Value: p.roles,
		},
		{
			Name:  "Site",
			Value: p.site,
		},
	}

	if p.password != nil && *p.password != "" {
		props = append(props, datastore.Property{Name: "Password", Value: p.password})
	}
	if p.created != nil {
		props = append(props, datastore.Property{Name: "Created", Value: p.created})
	}
	if p.lastSignin != nil {
		props = append(props, datastore.Property{Name: "LastSignin", Value: p.lastSignin})
	}

	var searchTags []interface{}
	searchTags = append(searchTags, strings.ToLower(p.email))
	idx := strings.Index(p.email, "@")
	if idx > 0 {
		searchTags = append(searchTags, strings.ToLower(p.email[idx+1:]))
	}

	fn := strings.ToLower(p.firstName)
	for _, r := range strings.Fields(fn) {
		searchTags = append(searchTags, r)
		for _, line := range FuzzyNameMatch {
			lineMatch := false
			for _, item := range line {
				if item == r {
					lineMatch = true
					break
				}
			}
			if lineMatch {
				for _, item := range line {
					if item != fn {
						searchTags = append(searchTags, item)
					}
				}
			}
		}
	}

	for _, r := range strings.Fields(strings.ToLower(p.lastName)) {
		searchTags = append(searchTags, r)
	}
	props = append(props, datastore.Property{Name: "SearchTags", Value: searchTags})

	return props, nil
}

func (p *GaePerson) Uuid() string {
	return p.uuid
}

func (p *GaePerson) FirstName() string {
	return p.firstName
}

func (p *GaePerson) LastName() string {
	return p.lastName
}

func (p *GaePerson) Site() string {
	return p.site
}

func (p *GaePerson) Email() string {
	return p.email
}

func (p *GaePerson) LastSigninIP() string {
	return p.lastSigninIP
}

func (p *GaePerson) LastSignin() *time.Time {
	return p.lastSignin
}

func (p *GaePerson) Created() *time.Time {
	return p.created
}

func (p *GaePerson) Roles() []string {
	return strings.FieldsFunc(p.roles, func(c rune) bool { return c == ':' })
}

func (p *GaePerson) DisplayName() string {
	return p.firstName + " " + p.lastName
}

func (p *GaePerson) HasPassword() bool {
	return !(p.password == nil || *p.password == "" || *p.password == "-")
}

func (p *GaePerson) HasRole(uid string) bool {
	if p.roleMap == nil {
		p.roleMap = make(map[string]bool)
		for _, v := range strings.FieldsFunc(p.roles, func(c rune) bool { return c == ':' }) {
			p.roleMap[v] = true
		}
	}

	_, found := p.roleMap[uid]
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

func NewGaeAccessManager(projectId, locationId string, locale *time.Location) (AccessManager, error, *datastore.Client, context.Context) {

	settings, client, ctx := NewGaeSetting(projectId)
	throttle := NewGaeThrottle(settings, client, ctx)

	t := template.New("api")
	var err error

	if t, err = t.Parse(emailHtmlTemplates); err != nil {
		return nil, errors.New(fmt.Sprintf("Email template problem: %v", err)), nil, nil
	}

	picklistStore := NewGaePicklistStore(projectId, client, ctx)

	return &GaeAccessManager{
		client:         client,
		ctx:            ctx,
		setting:        settings,
		throttle:       throttle,
		picklistStore:  picklistStore,
		template:       t,
		systemSessions: map[string]Session{},
		personCache:    gcache.New(200).LRU().Expiration(time.Second * 240).Build(),
		systemCache:    gcache.New(200).LRU().Expiration(time.Second * 120).Build(),
		sessionCache:   gcache.New(200).LRU().Expiration(time.Second * 60).Build(),
		ipCache:        gcache.New(30).LRU().Expiration(time.Second * 120).Build(),
		projectId:      projectId,
		locationId:     locationId,
		defaultLocale:  locale,
	}, nil, client, ctx
}

func (c *GaeAccessManager) Setting() Setting {
	return c.setting
}

func (c *GaeAccessManager) PicklistStore() PicklistStore {
	return c.picklistStore
}

func (a *GaeAccessManager) Signup(site, first_name, last_name, email, password, ip, userAgent, lang string) (*[]string, string, error) {
	var results []string

	session := a.GuestSession(site, ip, userAgent, lang)
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

	ui := &NewUserInfo{
		Site:      site,
		FirstName: first_name,
		LastName:  last_name,
		Email:     email,
		Password:  HashPassword(password),
	}
	data, merr := json.Marshal(ui)
	if merr != nil {
		results = append(results, "Internal server error. "+merr.Error())
		a.Info(session, "auth", "doSignup() mashal error: %v", merr.Error())
	}

	// Generate a unique identifying token to include in the email for authentication
	// that thie receipient of the email is the person who created this account
	token, err := uuid.NewUUID()
	if err != nil {
		return nil, "", err
	}
	a.Debug(session, "auth", "Sign up confirmation token for \"%s\" is \"%s\"", email, token.String())

	//TODO: expiry time set to actual desired expiry time

	k := datastore.NameKey("RequestToken", token.String(), nil)
	k.Namespace = site
	i := GaeRequestToken{Uuid: token.String(), PersonUuid: token.String(), Type: `signup_confirmation`, IP: ip, Expiry: time.Now().Unix(), Data: string(data)}
	if _, err := a.client.Put(a.ctx, k, &i); err != nil {
		return nil, "", err
	}

	baseUrl := a.Setting().GetWithDefault(site, "base.url", "")
	supportName := a.Setting().GetWithDefault(site, "support_team.name", "")
	supportEmail := a.Setting().GetWithDefault(site, "support_team.email", "")

	type EmailTemplateData struct {
		Site      string
		BaseURL   string
		Uuid      string
		FirstName string
		LastName  string
		ToEmail   string
		ToName    string
		FromEmail string
		FromName  string
		Subject   string
		Token     string
	}
	t := &EmailTemplateData{}
	t.Site = site
	t.ToEmail = email
	t.ToName = strings.TrimSpace(first_name + " " + last_name)
	t.FromEmail = supportEmail
	t.FromName = supportName
	t.Uuid = token.String()
	t.LastName = last_name
	t.FirstName = first_name
	t.Token = token.String()
	if baseUrl == "" {
		t.BaseURL = "http://" + site
	} else {
		t.BaseURL = baseUrl
	}

	var textBuffer bytes.Buffer
	err = a.template.ExecuteTemplate(&textBuffer, "signup_confirmation_text", t)
	if err != nil {
		results = append(results, fmt.Sprintf("Error rendering template \"signup_confirmation_text\": %v", err))
		return &results, "", errors.New(results[0])
	}

	var htmlBuffer bytes.Buffer
	err = a.template.ExecuteTemplate(&htmlBuffer, "signup_confirmation_html", t)
	if err != nil {
		results = append(results, fmt.Sprintf("Error rendering template \"signup_confirmation_html\": %v", err))
		return &results, "", errors.New(results[0])
	}

	sendResults, err := SendEmail(a, session, t.Subject, t.ToEmail, t.ToName, textBuffer.Bytes(), htmlBuffer.Bytes())
	if sendResults != nil && len(*sendResults) != 0 {
		return sendResults, token.String(), err
	}
	if err != nil {
		return sendResults, token.String(), err
	}

	return nil, token.String(), nil
}

func (a *GaeAccessManager) ForgotPasswordRequest(site, email, ip, userAgent, lang string) (string, error) {
	session := a.GuestSession(site, ip, "", "")
	email = strings.ToLower(strings.TrimSpace(email))

	if email == "" {
		return "", nil
	}

	a.Debug(session, `auth`, "ForgotPasswordRequest received for: %s", email)

	syslog := NewGaeSyslogBundle(site, a.client, a.ctx)
	defer syslog.Put()

	for _, preauth := range a.preAuthenticationHandlers {
		preauth(a, session, email)
	}

	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email = ", email).Limit(1)
	_, err := a.client.GetAll(a.ctx, q, &items)
	if err != nil {
		a.Error(session, `auth`, "ForgotPasswordRequest Person lookup Error: %v", err)
		return "", err
	}
	if len(items) == 0 {
		a.Info(session, `auth`, "ForgotPasswordRequest called with unknown email address: %s", email)
		return "", nil
	}
	if items[0].password == nil || *items[0].password == "" {
		a.Warning(session, `security`, "ForgotPassword calld on account with an empty password: %s", email)
		return "", nil
	}

	token, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	supportName := a.setting.GetWithDefault(site, "support_team.name", "")
	supportEmail := a.setting.GetWithDefault(site, "support_team.email", "")
	baseUrl := a.setting.GetWithDefault(site, "base.url", "")

	type EmailTemplateData struct {
		Site      string
		BaseURL   string
		Subject   string
		FirstName string
		LastName  string
		ToEmail   string
		ToName    string
		FromEmail string
		FromName  string
		Email     string
		Token     string
	}
	t := &EmailTemplateData{}
	t.Site = site
	t.ToEmail = email
	t.ToName = strings.TrimSpace(items[0].FirstName() + " " + items[0].LastName())
	t.Token = token.String()
	t.FirstName = items[0].FirstName()
	t.LastName = items[0].LastName()
	t.Subject = "Lost password request"
	t.FromEmail = supportEmail
	t.FromName = supportName
	if baseUrl == "" {
		t.BaseURL = "http://" + site
	} else {
		t.BaseURL = baseUrl
	}

	k := datastore.NameKey("RequestToken", token.String(), nil)
	k.Namespace = site
	i := GaeRequestToken{Uuid: token.String(), PersonUuid: items[0].Uuid(), Type: `password_reset`, IP: ip, Expiry: time.Now().Unix(), Data: ""}
	if _, err := a.client.Put(a.ctx, k, &i); err != nil {
		return "Unable to process password reset request. Please try again.", err
	}

	var textBuffer bytes.Buffer
	err = a.template.ExecuteTemplate(&textBuffer, "lost_password_text", t)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error rendering template \"lost_password_text\": %v", err))
	}

	var htmlBuffer bytes.Buffer
	err = a.template.ExecuteTemplate(&htmlBuffer, "lost_password_html", t)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error rendering template \"lost_password_html\": %v", err))
	}

	sendResults, err := SendEmail(a, session, t.Subject, t.ToEmail, t.ToName, textBuffer.Bytes(), htmlBuffer.Bytes())
	if sendResults != nil && len(*sendResults) != 0 {
		return token.String(), err
	}
	if err != nil {
		return token.String(), err
	}

	return token.String(), nil
}

func (g *GaeAccessManager) Authenticate(site, email, password, ip, userAgent, lang string) (Session, string, error) {
	if email == "" {
		return g.GuestSession(site, ip, userAgent, lang), "Invalid email address or password.", nil
	}
	session := g.GuestSession(site, ip, userAgent, lang)
	for _, preauth := range g.preAuthenticationHandlers {
		preauth(g, session, email)
	}

	syslog := NewGaeSyslogBundle(site, g.client, g.ctx)
	defer syslog.Put()
	syslog.Add(`auth`, ip, `debug`, ``, fmt.Sprintf("Authentication attempt for '%s'", email))

	email = strings.ToLower(strings.TrimSpace(email))
	if throttled, _ := g.throttle.IsThrottled(email); throttled {
		syslog.Add(`auth`, ip, `info`, ``, fmt.Sprintf("Authentication for '%s' blocked by throttle", email))
		return g.GuestSession(site, ip, userAgent, lang), "Repeated signin failures were detected from your location, please wait a few minutes and try again.", nil
	}

	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email = ", email).Limit(1)
	_, err := g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		syslog.Add(`auth`, ip, `error`, ``, fmt.Sprintf("Authenticate() Person lookup Error: %v", err))
		return session, "", err
	}
	if len(items) > 0 {
		if items[0].password == nil || *items[0].password == "" {
			g.throttle.Increment(email)
			syslog.Add(`auth`, ip, `warn`, items[0].Uuid(), fmt.Sprintf("Authentication for '%s' blocked. Account has no password.", email))
			return session, "Invalid email address or password.", nil
		}

		// Check internal password
		if !VerifyPassword(*items[0].password, password) {
			// Internal password check failed

			externallyAuthenticated := false
			for _, auth := range g.authenticationHandlers {
				ok, err := auth(g, session, email, password)
				if ok {
					syslog.Add(`auth`, ip, `debug`, items[0].Uuid(), fmt.Sprintf("External Authentication for '%s' succeeded.", email))
					externallyAuthenticated = true
					break
				}
				if err != nil {
					syslog.Add(`auth`, ip, `warning`, items[0].Uuid(), fmt.Sprintf("External Authentication for '%s' failed. Error: %v", email, err))
					return g.GuestSession(site, ip, userAgent, lang), "Communication with authentication service failed. Please try again.", nil
				}
			}

			if !externallyAuthenticated {
				g.throttle.Increment(email)
				syslog.Add(`auth`, ip, `notice`, items[0].Uuid(), fmt.Sprintf("Authentication for '%s' failed. Incorrect password.", email))
				return g.GuestSession(site, ip, userAgent, lang), "Invalid email address or password.", nil
			}
		}

		// Password matched
		now := time.Now()
		items[0].lastSignin = &now
		items[0].lastSigninIP = ip
		k := datastore.NameKey("Person", items[0].Uuid(), nil)
		k.Namespace = site
		if _, err := g.client.Put(g.ctx, k, &items[0]); err != nil {
			syslog.Add(`auth`, ip, `error`, items[0].Uuid(), fmt.Sprintf("Authenticate() Person update Error: %v", err))
			return session, "", err
		}

		token, err2 := g.createSession(site, items[0].Uuid(), items[0].FirstName(), items[0].LastName(), items[0].Email(), items[0].roles, ip)
		if err2 != nil {
			syslog.Add(`auth`, ip, `error`, items[0].Uuid(), fmt.Sprintf("Authenticate() Session creation error: %v", err2))
			return g.GuestSession(site, ip, userAgent, lang), "", err2
		}
		syslog.Add(`auth`, ip, `info`, items[0].Uuid(), fmt.Sprintf("Authentication success for '%s'", email))

		session = &GaeSession{
			site:          site,
			ip:            ip,
			personUUID:    items[0].Uuid(),
			token:         token,
			firstName:     items[0].FirstName(),
			lastName:      items[0].LastName(),
			email:         items[0].Email(),
			roles:         items[0].roles,
			csrf:          RandomString(8),
			authenticated: true,
			roleMap:       nil,
			locale:        g.defaultLocale,
		}

		return session, "", nil
	}

	// User lookup failed
	if throttled, _ := g.throttle.IsThrottled(ip); throttled {
		// An invalid email address was entered. If this occurs too many times, stop reporting
		// back the normal "Invalid email address or password" message prevent the signin form
		// revealing to a bot that this email address/password combination is invalid.
		syslog.Add(`auth`, ip, `debug`, ``, fmt.Sprintf("Authentication for '%s' blocked by throttle", email))
		return g.GuestSession(site, ip, userAgent, lang), "Repeated signin failures were detected, please wait a few minutes and try again.", nil
	}

	g.throttle.Increment(ip)
	syslog.Add(`auth`, ip, `notice`, ``, fmt.Sprintf("Authentication for '%s' failed: Unknown email address.", email))
	return g.GuestSession(site, ip, userAgent, lang), "Invalid email address or password.", nil
}

type GaeWatch struct {
	ObjectUuid string
	ObjectName string
	ObjectType string
	PersonUuid string
	PersonName string
}

func (w *GaeWatch) GetObjectUuid() string {
	return w.ObjectUuid
}

func (w *GaeWatch) GetObjectName() string {
	return w.ObjectName
}

func (w *GaeWatch) GetObjectType() string {
	return w.ObjectType
}

func (w *GaeWatch) GetPersonUuid() string {
	return w.PersonUuid
}

func (w *GaeWatch) GetPersonName() string {
	return w.PersonName
}

func (am *GaeAccessManager) StartWatching(objectUuid, objectName, objectType string, requestor Session) error {
	if objectUuid == "" {
		return errors.New("Invalid object uuid.")
	}

	pkey := datastore.NameKey(objectType, objectUuid, nil)
	pkey.Namespace = requestor.Site()
	key := datastore.NameKey("Watch", objectUuid+"|"+requestor.PersonUuid(), pkey)
	key.Namespace = requestor.Site()

	w := GaeWatch{
		PersonName: requestor.DisplayName(),
		PersonUuid: requestor.PersonUuid(),
		ObjectUuid: objectUuid,
		ObjectType: objectType,
		ObjectName: objectName,
	}
	if _, err := am.client.Put(am.ctx, key, &w); err != nil {
		return err
	}

	return nil
}

func (am *GaeAccessManager) StopWatching(objectUuid, objectType string, requestor Session) error {
	if objectUuid == "" {
		return errors.New("Invalid object uuid.")
	}

	pkey := datastore.NameKey(objectType, objectUuid, nil)
	pkey.Namespace = requestor.Site()
	key := datastore.NameKey("Watch", objectUuid+"|"+requestor.PersonUuid(), pkey)
	key.Namespace = requestor.Site()
	if err := am.client.Delete(am.ctx, key); err != nil {
		return err
	}

	return nil
}

func (am *GaeAccessManager) GetConnectorInfo() []*ConnectorInfo {
	return am.connectorInfo[:]
}

// GetConnectorInfoByLabel returns the information about a specific connector.
func (am *GaeAccessManager) GetConnectorInfoByLabel(label string) *ConnectorInfo {
	for _, connector := range am.connectorInfo {
		if connector.Label == label {
			return connector
		}
	}
	return nil
}

func (am *GaeAccessManager) RegisterConnectorInfo(connector *ConnectorInfo) {
	am.connectorInfo = append(am.connectorInfo, connector)
}

func (am *GaeAccessManager) RegisterNotificationEventHandler(handler NotificationEventHandler) {
	am.notificationEventHandlers = append(am.notificationEventHandlers, handler)
}

func (am *GaeAccessManager) RegisterAuthenticationHandler(handler AuthenticationHandler) {
	am.authenticationHandlers = append(am.authenticationHandlers, handler)
}

func (am *GaeAccessManager) RegisterPreAuthenticationHandler(handler PreAuthenticationHandler) {
	am.preAuthenticationHandlers = append(am.preAuthenticationHandlers, handler)
}

func (am *GaeAccessManager) TriggerNotificationEvent(objectUuid string, session Session) error {
	var watchers []Watch

	watchers, err := am.GetWatchers(objectUuid, session)
	if err != nil {
		return err
	}

	for _, watcher := range watchers {
		handled := false
		for _, handler := range am.notificationEventHandlers {
			done, err := handler(watcher, session, am)
			if err != nil {
				return err
			}
			if done {
				handled = true
				break
			}
		}
		if !handled {
			fmt.Println("Unhandled notification event", watcher)
		}

	}

	return nil
}

func (am *GaeAccessManager) GetWatching(requestor Session) ([]Watch, error) {
	var items []Watch

	q := datastore.NewQuery("Watch").Namespace(requestor.Site()).Filter("PersonUuid =", requestor.PersonUuid()).Limit(200)
	it := am.client.Run(am.ctx, q)
	for {
		w := new(GaeWatch)
		if _, err := it.Next(w); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		items = append(items, w)
	}

	return items[:], nil
}

func (am *GaeAccessManager) GetWatchers(objectUuid string, requestor Session) ([]Watch, error) {
	var items []Watch

	q := datastore.NewQuery("Watch").Namespace(requestor.Site()).Filter("ObjectUuid =", objectUuid).Limit(200)
	it := am.client.Run(am.ctx, q)
	for {
		w := new(GaeWatch)
		if _, err := it.Next(w); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		items = append(items, w)
	}

	return items[:], nil
}

func (am *GaeAccessManager) GetPersonCached(uuid string, session Session) (Person, error) {
	if uuid == "" || session == nil {
		return nil, nil
	}

	if !session.IsAuthenticated() {
		return nil, errors.New("Permission denied.")
	}

	var person Person
	v, _ := am.personCache.Get(uuid)
	if v != nil {
		person = v.(Person)
		// If user is not admin, only return a subset of fields
		if !session.HasRole("s1") && session.PersonUuid() != uuid {
			info := &GaePerson{
				uuid:      person.Uuid(),
				firstName: person.FirstName(),
				lastName:  person.LastName(),
			}
			return info, nil
		}
		return person, nil
	}

	// Not in cache, load it
	k := datastore.NameKey("Person", uuid, nil)
	k.Namespace = session.Site()
	i := new(GaePerson)
	err := am.client.Get(am.ctx, k, i)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	am.personCache.Set(uuid, i)

	// If user is not admin, only return a subset of fields
	if !session.HasRole("s1") && session.PersonUuid() != uuid {
		info := &GaePerson{
			uuid:      i.Uuid(),
			firstName: i.FirstName(),
			lastName:  i.LastName(),
		}
		return info, nil
	}

	return i, nil
}

func (am *GaeAccessManager) GetPerson(uuid string, session Session) (Person, error) {
	if uuid == "" {
		return nil, nil
	}

	if !session.IsAuthenticated() {
		return nil, errors.New("Permission denied.")
	}

	k := datastore.NameKey("Person", uuid, nil)
	k.Namespace = session.Site()
	i := new(GaePerson)
	err := am.client.Get(am.ctx, k, i)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	am.personCache.Set(uuid, i)

	if !session.HasRole("s1") && session.PersonUuid() != uuid {
		info := &GaePerson{
			uuid:      i.Uuid(),
			firstName: i.FirstName(),
			lastName:  i.LastName(),
		}
		return info, nil
	}

	return i, nil
}

func (am *GaeAccessManager) GetPeople(requestor Session) ([]Person, error) {
	var items []Person

	if !requestor.HasRole("s1") {
		return items, errors.New("Permission denied.")
	}

	q := datastore.NewQuery("Person").Namespace(requestor.Site()).Limit(2000)
	it := am.client.Run(am.ctx, q)
	for {
		e := new(GaePerson)
		if _, err := it.Next(e); err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		e.site = requestor.Site()
		items = append(items, e)
	}

	return items[:], nil
}

// SetPassword changes the password for a person. A user may update their own password or someone with the "Manage Account" role.
func (am *GaeAccessManager) SetPassword(personUuid, password string, updator Session) error {

	k := datastore.NameKey("Person", personUuid, nil)
	k.Namespace = updator.Site()
	i := new(GaePerson)
	err := am.client.Get(am.ctx, k, i)
	if err == datastore.ErrNoSuchEntity {
		return errors.New("Person not found.")
	} else if err != nil {
		return err
	}

	if !updator.HasRole("s3") && updator.PersonUuid() != personUuid {
		if i.password != nil && *i.password != "" {
			return errors.New("Permission denied.")
		}
	}

	bulk := &GaeEntityAuditLogCollection{}
	bulk.SetEntityUuidPersonUuid(personUuid, updator.PersonUuid(), updator.DisplayName())
	if len(password) > 0 {
		bulk.AddItem("Password", "", "")
		i.password = HashPassword(password)
	}
	if bulk.HasUpdates() {
		if err = am.AddEntityChangeLog(bulk, updator); err != nil {
			am.Error(updator, `datastore`, "SetPerson() failed persisting changelog. Error: %v", err)
			return err
		}
		if _, err := am.client.Put(am.ctx, k, i); err != nil {
			am.Error(updator, `datastore`, "SetPerson() failed. Error: %v", err)
			return err
		}
	}
	return nil

}

func (am *GaeAccessManager) UpdatePerson(uuid, firstName, lastName, email, roles, password string, updator Session) error {
	if !updator.HasRole("s3") && updator.PersonUuid() != uuid {
		return errors.New("Permission denied.")
	}

	if password != "" {
		passwordCheck := PasswordStrength(password)
		if len(passwordCheck) > 0 {
			return errors.New("Password is insecure. " + passwordCheck[0])
		}
	}

	check, err := am.GetPersonByEmail(updator.Site(), email, updator)
	if err != nil {
		return err
	}
	if check != nil && check.Uuid() != uuid {
		return errors.New("A user account already exists with this email address.")
	}

	k := datastore.NameKey("Person", uuid, nil)
	k.Namespace = updator.Site()
	i := new(GaePerson)
	err = am.client.Get(am.ctx, k, i)
	if err == datastore.ErrNoSuchEntity {
		return errors.New("Person not found.")
	} else if err != nil {
		return err
	}

	// Normal users may not update their own system roles
	if !updator.HasRole("s3") && updator.PersonUuid() == uuid {
		if roles != i.roles {
			return errors.New("Permission denied.")
		}
	}

	bulk := &GaeEntityAuditLogCollection{}
	bulk.SetEntityUuidPersonUuid(uuid, updator.PersonUuid(), updator.DisplayName())
	if firstName != i.FirstName() {
		bulk.AddItem("FirstName", i.firstName, firstName)
		i.firstName = firstName
	}
	if lastName != i.lastName {
		bulk.AddItem("LastName", i.lastName, lastName)
		i.lastName = lastName
	}
	if email != i.email {
		bulk.AddItem("Email", i.email, email)
		i.email = email
	}
	if roles != i.roles {
		bulk.AddItem("Roles", i.roles, roles)
		i.roles = roles
	}
	if len(password) > 0 {
		bulk.AddItem("Password", "", "")
		i.password = HashPassword(password)
	}
	if bulk.HasUpdates() {
		if err = am.AddEntityChangeLog(bulk, updator); err != nil {
			am.Error(updator, `datastore`, "UpdatePerson() failed persisting changelog. Error: %v", err)
			return err
		}
		if _, err := am.client.Put(am.ctx, k, i); err != nil {
			am.Error(updator, `datastore`, "UpdatePerson() failed. Error: %v", err)
			return err
		}
	}
	return nil
}

func (am *GaeAccessManager) DeletePerson(uuid string, updator Session) error {
	if !updator.HasRole("s3") {
		return errors.New("Permission denied.")
	}

	k := datastore.NameKey("Person", uuid, nil)
	k.Namespace = updator.Site()

	if err := am.client.Delete(am.ctx, k); err != nil {
		return err
	}
	return nil
}

func (am *GaeAccessManager) SearchPeople(query string, requestor Session) ([]Person, error) {
	if !requestor.HasRole("s1") {
		return []Person{}, errors.New("Permission denied.")
	}

	results := make([]Person, 0)

	fields := strings.Fields(strings.ToLower(query))
	sort.Slice(fields, func(i, j int) bool {
		return len(fields[j]) < len(fields[i])
	})

	if len(fields) == 0 {
		return results, nil
	} else if len(fields) == 1 {
		q := datastore.NewQuery("Person").Namespace(requestor.Site()).Filter("SearchTags =", fields[0]).Limit(50)
		it := am.client.Run(am.ctx, q)
		for {
			e := new(GaePerson)
			if _, err := it.Next(e); err == iterator.Done {
				break
			} else if err != nil {
				return nil, err
			}
			results = append(results, e)
		}
	} else if len(fields) > 1 {
		q := datastore.NewQuery("Student").Namespace(requestor.Site()).Filter("SearchTags =", fields[0]).Filter("SearchTags =", fields[1]).Limit(50)
		it := am.client.Run(am.ctx, q)
		for {
			e := new(GaePerson)
			if _, err := it.Next(e); err == iterator.Done {
				break
			} else if err != nil {
				return nil, err
			}
			results = append(results, e)
		}
	}

	return results, nil

}

func (g *GaeAccessManager) GetPersonByFirstNameLastName(site, firstname, lastname string, requestor Session) (Person, error) {
	if firstname == "" && lastname == "" {
		return nil, nil
	}

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

	items[0].site = site
	return &items[0], nil
}

func (g *GaeAccessManager) CheckEmailExists(site, email string) (bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email =", email).Limit(1)
	_, err := g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		return false, err
	}
	if len(items) == 0 {
		return false, nil
	}
	return true, nil
}

func (g *GaeAccessManager) GetPersonByEmail(site, email string, requestor Session) (Person, error) {
	if email == "" {
		return nil, nil
	}

	if requestor != nil && !requestor.HasRole("s1") {
		return nil, errors.New("Permission denied.")
	}

	email = strings.TrimSpace(email)
	email = strings.ToLower(email)

	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email =", email).Limit(2)
	_, err := g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) > 1 {
		return nil, errors.New("Multiple accounts have this email address")
	}

	items[0].site = site
	return &items[0], nil
}

// Request the session information associated the site hostname and cookie in the web request
func (g *GaeAccessManager) GetSystemSession(site, firstname, lastname string) (Session, error) {
	return g.GetSystemSessionWithRoles(site, firstname, lastname, "s1:s2:s3:s4")
}

// Request the session information associated the site hostname and cookie in the web request
func (g *GaeAccessManager) GetSystemSessionWithRoles(site, firstname, lastname, roles string) (Session, error) {
	found, ok := g.systemSessions[site+"|"+firstname+"|"+lastname]
	if ok {
		return found, nil
	}

	now := time.Now()
	firstname = strings.TrimSpace(firstname)
	lastname = strings.TrimSpace(lastname)

	person, err := g.GetPersonByFirstNameLastName(site, firstname, lastname, nil)
	if err != nil {
		return nil, err
	}
	puuid := ""
	if person != nil {
		puuid = person.Uuid()
	}
	if person == nil || (person.(*GaePerson)).roles != roles {

		if person == nil {
			uuid, err := uuid.NewUUID()
			if err != nil {
				return nil, err
			}
			person = &GaePerson{
				uuid:      uuid.String(),
				site:      site,
				firstName: firstname,
				lastName:  lastname,
				roles:     roles,
				nameKey:   strings.ToLower(firstname + "|" + lastname),
				created:   &now,
			}
		}
		(person.(*GaePerson)).roles = roles

		k := datastore.NameKey("Person", person.Uuid(), nil)
		k.Namespace = site
		if _, err := g.client.Put(g.ctx, k, person); err != nil {
			g.Error(g.GuestSession(site, "", "", ""), `datastore`, "GetSystemSession() Person creation failed. Error: %v", err)
			return nil, err
		}
		puuid = person.Uuid()
	}

	token := RandomString(32)
	session := &GaeSession{
		site:          site,
		ip:            "",
		personUUID:    puuid,
		token:         token,
		firstName:     firstname,
		lastName:      lastname,
		authenticated: true,
		csrf:          RandomString(8),
		roles:         roles,
		roleMap:       nil, // built on demand
		locale:        g.defaultLocale,
	}

	g.systemSessions[site+"|"+firstname+"|"+lastname] = session

	return session, nil
}

// AddPerson creates a new user account. Email must be unique to the system. Password must already be hashed, or nil. Returns the uuid of the created account
func (g *GaeAccessManager) AddPerson(site, firstName, lastName, email, roles string, password *string, ip string, requestor Session) (string, error) {
	if requestor != nil && !requestor.HasRole("s1") {
		return "", errors.New("Permission denied.")
	}

	firstName = strings.TrimSpace(firstName)
	lastName = strings.TrimSpace(lastName)
	email = strings.ToLower(strings.TrimSpace(email))

	check, err := g.GetPersonByEmail(site, email, requestor)
	if err != nil {
		return "", err
	}
	if check != nil {
		return "", errors.New("A user account already exists with this email address.")
	}

	// Password is hashed, this doesnt make sense
	/*
		if password != nil {
			passwordCheck := PasswordStrength(*password)
			if len(passwordCheck) > 0 {
				return "", errors.New("Password is insecure. " + passwordCheck[0])
			}
	}*/

	syslog := NewGaeSyslogBundle(site, g.client, g.ctx)
	defer syslog.Put()

	uuid, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	si := &GaePerson{
		uuid:      uuid.String(),
		site:      site,
		firstName: firstName,
		lastName:  lastName,
		email:     email,
		roles:     roles,
		password:  password,
		nameKey:   strings.ToLower(firstName + "|" + lastName),
		created:   &now,
	}

	if requestor == nil {
		requestor = &GaeSession{
			site:       site,
			personUUID: si.uuid,
			firstName:  firstName,
			lastName:   lastName,
			email:      email,
			roles:      roles,
		}
	}

	bulk := &GaeEntityAuditLogCollection{}
	bulk.SetEntityUuidPersonUuid(uuid.String(), requestor.PersonUuid(), requestor.DisplayName())

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
		g.Error(requestor, `datastore`, "AddPerson() failed persisting changelog. Error: %v", err)
		return "", err
	}

	k := datastore.NameKey("Person", uuid.String(), nil)
	k.Namespace = site
	if _, err := g.client.Put(g.ctx, k, si); err != nil {
		syslog.Add(`datastore`, ip, `error`, ``, fmt.Sprintf("AddPerson() Person storage failed. Error: %v", err))
		return "", err
	}
	syslog.Add(`auth`, ip, `notice`, uuid.String(), fmt.Sprintf("New user account created '%s','%s','%s'", firstName, lastName, email))

	return uuid.String(), nil
}

func (g *GaeAccessManager) ActivateSignup(site, token, ip string) (string, string, error) {
	syslog := NewGaeSyslogBundle(site, g.client, g.ctx)
	defer syslog.Put()

	if token == "" {
		return "", "Invalid account activation token", nil
	}

	// Check the token is a valid uuid
	_, err := uuid.Parse(token)
	if err != nil {
		syslog.Add(`auth`, ip, `error`, ``, fmt.Sprintf("ActivateSignup() called with invalid activation token"))
		return "", "Invalid account activation token", nil
	}

	// Lookup the request token for the account creation request details
	maxAge := g.setting.GetInt(site, "activation_token.max_age", 2592000)
	k := datastore.NameKey("RequestToken", token, nil)
	k.Namespace = site
	si := new(GaeRequestToken)
	err = g.client.Get(g.ctx, k, si)
	if err == datastore.ErrNoSuchEntity {
		syslog.Add(`auth`, ip, `error`, ``, "ActivateSignup() called with activation token not in the datastore.")
		return "", "Invalid activation token", nil
	} else if err != nil {
		syslog.Add(`auth`, ip, `error`, ``, "ActivateSignup() failure: "+err.Error())
		return "", "Activation service failed, please try again.", err
	} else if si.Expiry+int64(maxAge) < time.Now().Unix() {
		syslog.Add(`auth`, ip, `error`, ``, fmt.Sprintf("ActivateSignup() called with expired activation token: %d < %d ", si.Expiry, time.Now().Unix()))
		return "", "Invalid activation token", nil
	}
	i := &NewUserInfo{}
	json.Unmarshal([]byte(si.Data), i)

	// Do one last final double check an account does not exist with this email address
	var items []GaePerson
	q := datastore.NewQuery("Person").Namespace(site).Filter("Email = ", i.Email).Limit(1)
	_, err = g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		syslog.Add(`auth`, ip, `error`, ``, "ActivateSignup() email lookup failure: "+err.Error())
		return "", "Activation service failed, please try again.", err
	}
	if len(items) > 0 {
		syslog.Add(`auth`, ip, `error`, ``, "ActivateSignup() Email address already exists: "+err.Error())
		return "", "Can't complete account activation, this email address has recently been activated by a different person.", nil
	}

	// NewUserInfo doesnt carry roles, should it?
	uuid, aerr := g.AddPerson(site, i.FirstName, i.LastName, i.Email, "", i.Password, ip, nil)
	if aerr != nil {
		syslog.Add(`auth`, ip, `error`, uuid, "AddPerson() failed: "+aerr.Error())
		return "", "", aerr
	}
	syslog.Add(`auth`, ip, `notice`, uuid, fmt.Sprintf("New user account activated '%s','%s','%s'", i.FirstName, i.LastName, i.Email))

	// NewUserInfo doesn't permit default/initial roles. Should it?
	token, err2 := g.createSession(site, uuid, i.FirstName, i.LastName, i.Email, "", ip)
	if err2 == nil {
		return token, "", nil
	}

	syslog.Add(`auth`, ip, `error`, uuid, "AddPerson() createSession() failure: "+err2.Error())
	return "", "", err2
}

func (g *GaeAccessManager) ResetPassword(site, token, password, ip string) (bool, string, error) {
	syslog := NewGaeSyslogBundle(site, g.client, g.ctx)
	defer syslog.Put()

	// Check the token is a valid uuid
	_, err := uuid.Parse(token)
	if err != nil {
		syslog.Add(`auth`, ip, `error`, ``, "ResetPassword() requested with invalid uuid.")
		return false, "Invalid password reset token.", nil
	}

	// Lookup the request token for the forgot password request details
	maxAge := g.setting.GetInt(site, "password_reset_token.max_age", 93600)
	k := datastore.NameKey("RequestToken", token, nil)
	k.Namespace = site
	si := new(GaeRequestToken)
	err = g.client.Get(g.ctx, k, si)
	if err == datastore.ErrNoSuchEntity {
		syslog.Add(`auth`, ip, `error`, ``, "ResetPassword() called with unknown uuid.")
		return false, "Unknown password reset token.", nil
	} else if err != nil {
		syslog.Add(`auth`, ip, `error`, ``, "ResetPassword() failure: "+err.Error())
		return false, "Password reset service failed, please try again.", err
	} else if si.Expiry+int64(maxAge) < time.Now().Unix() {
		syslog.Add(`auth`, ip, `error`, ``, fmt.Sprintf("ResetPassword() called with expired uuid: %v < %v ", si.Expiry, time.Now()))
		return false, "This password reset link has expired.", nil
	}

	// Do one last final double check an account does not exist with this email address
	var person GaePerson
	k = datastore.NameKey("Person", si.PersonUuid, nil)
	k.Namespace = site
	err = g.client.Get(g.ctx, k, &person)
	if err == datastore.ErrNoSuchEntity {
		syslog.Add(`auth`, ip, `error`, ``, "Password Reset token pointed to unknown person uuid")
		return false, "Reset password service failed, please try again.", err
	} else if err != nil {
		syslog.Add(`auth`, ip, `error`, ``, "ResetPassword() datastore error: "+err.Error())
		return false, "Reset password service failed, please try again.", err
	}
	person.password = HashPassword(password)
	_, err = g.client.Put(g.ctx, k, &person)
	if err == nil {
		syslog.Add(`auth`, ip, `error`, person.Uuid(), "ResetPassword success")
		return true, "Your password has been reset", nil
	} else {
		return false, "Password reset failed. Please try again shortly.", err
	}
}

type GaeScheduledConnector struct {
	Uuid               string      `json:",omitempty"`
	ExternalSystemUuid string      `json:",omitempty"`
	Label              string      `json:",omitempty"`
	Config             []*KeyValue `json:",omitempty" datastore:",noindex"`
	Data               []*KeyValue `json:",omitempty" datastore:",noindex"`
	Description        string      `json:",omitempty" datastore:",noindex"`
	Frequency          string      `json:",omitempty" datastore:",noindex"` // daily, hourly, weekly
	Hour               int         `json:",omitempty" datastore:",noindex"` // if hourly/weekly, what hour
	Day                int         `json:",omitempty" datastore:",noindex"` // if weekly, what day
	LastRun            *time.Time  `json:",omitempty"`
	Disabled           bool
}

func (s *GaeScheduledConnector) String() string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (s *GaeScheduledConnector) ToScheduledConnector() *ScheduledConnector {
	return &ScheduledConnector{
		Uuid:               s.Uuid,
		ExternalSystemUuid: s.ExternalSystemUuid,
		Label:              s.Label,
		Config:             s.Config,
		Data:               s.Data,
		Frequency:          s.Frequency,
		Hour:               s.Hour,
		Day:                s.Day,
		LastRun:            s.LastRun,
		Description:        s.Description,
		Disabled:           s.Disabled,
	}
}

func (am *GaeAccessManager) GetScheduledConnectors(requestor Session) ([]*ScheduledConnector, error) {
	var items []*GaeScheduledConnector

	q := datastore.NewQuery("ScheduledConnector").Namespace(requestor.Site()).Limit(500)
	_, err := am.client.GetAll(am.ctx, q, &items)
	if err != nil {
		return nil, err
	}

	results := make([]*ScheduledConnector, len(items), len(items))
	for i, o := range items {
		results[i] = o.ToScheduledConnector()

		// This is only known at runtime, dont persist
		results[i].SetConfig("google.project", am.projectId)
		results[i].SetConfig("google.location", am.locationId)
	}

	return results, nil
}

func (am *GaeAccessManager) GetScheduledConnector(uuid string, requestor Session) (*ScheduledConnector, error) {
	if uuid == "" {
		return nil, errors.New("Invalid value for `uuid` parameter: " + uuid)
	}

	k := datastore.NameKey("ScheduledConnector", uuid, nil)
	k.Namespace = requestor.Site()

	var i GaeScheduledConnector
	if err := am.client.Get(am.ctx, k, &i); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, nil
		}
		return nil, err
	}

	s := i.ToScheduledConnector()

	// This is only known at runtime, dont persist
	s.SetConfig("google.project", am.projectId)
	s.SetConfig("google.location", am.locationId)

	return s, nil
}

func (am *GaeAccessManager) AddScheduledConnector(connector *ScheduledConnector, updator Session) error {
	if connector.Uuid != "" {
		return errors.New("Invalid value for `uuid` parameter: " + connector.Uuid)
	}
	uuid, err := uuid.NewUUID()
	if err != nil {
		return err
	}
	connector.Uuid = uuid.String()

	// Ensure transient data is not persisted
	connector.SetConfig("google.project", "")
	connector.SetConfig("google.location", "")

	k := datastore.NameKey("ScheduledConnector", uuid.String(), nil)
	k.Namespace = updator.Site()

	i := &GaeScheduledConnector{
		Uuid:               connector.Uuid,
		ExternalSystemUuid: connector.ExternalSystemUuid,
		Label:              connector.Label,
		Config:             connector.Config,
		Data:               connector.Data,
		Frequency:          connector.Frequency,
		Hour:               connector.Hour,
		Day:                connector.Day,
		LastRun:            connector.LastRun,
		Description:        connector.Description,
		Disabled:           connector.Disabled,
	}
	if _, err := am.client.Put(am.ctx, k, i); err != nil {
		return err
	}

	return nil
}

func (am *GaeAccessManager) UpdateScheduledConnector(connector *ScheduledConnector, updator Session) error {
	if connector.Uuid == "" {
		return errors.New("Invalid value for `uuid` parameter: " + connector.Uuid)
	}
	k := datastore.NameKey("ScheduledConnector", connector.Uuid, nil)
	k.Namespace = updator.Site()

	// Ensure transient data is not persisted
	connector.SetConfig("google.project", "")
	connector.SetConfig("google.location", "")

	var current GaeScheduledConnector
	if err := am.client.Get(am.ctx, k, &current); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil
		}
		return err
	}

	bulk := &GaeEntityAuditLogCollection{}
	bulk.SetEntityUuidPersonUuid(connector.Uuid, updator.PersonUuid(), updator.DisplayName())

	if connector.Day != current.Day {
		bulk.AddIntItem("Day", int64(current.Day), int64(connector.Day))
		current.Day = connector.Day
	}

	if connector.Hour != current.Hour {
		bulk.AddIntItem("Hour", int64(current.Hour), int64(connector.Hour))
		current.Hour = connector.Hour
	}

	if connector.Frequency != current.Frequency {
		bulk.AddItem("Frequency", current.Frequency, connector.Frequency)
		current.Frequency = connector.Frequency
	}

	if connector.ExternalSystemUuid != current.ExternalSystemUuid {
		bulk.AddItem("ExternalSystemUuid", current.ExternalSystemUuid, connector.ExternalSystemUuid)
		current.ExternalSystemUuid = connector.ExternalSystemUuid
	}

	if connector.Description != current.Description {
		bulk.AddItem("Description", current.Description, connector.Description)
		current.Description = connector.Description
	}

	if connector.Disabled != current.Disabled {
		bulk.AddBoolItem("Disabled", current.Disabled, connector.Disabled)
		current.Disabled = connector.Disabled
	}

	if !MatchingDate(connector.LastRun, current.LastRun) {
		bulk.AddDateItem("LastRun", current.LastRun, connector.LastRun)
		current.LastRun = connector.LastRun
	}

	SyncKeyValueList("Data", &connector.Data, &current.Data, bulk)
	SyncKeyValueList("Config", &connector.Config, &current.Config, bulk)

	if bulk.HasUpdates() {
		if err := am.AddEntityChangeLog(bulk, updator); err != nil {
			return err
		}
		if _, err := am.client.Put(am.ctx, k, &current); err != nil {
			return err
		}
	}

	return nil
}

func (am *GaeAccessManager) DeleteScheduledConnector(uuid string, updator Session) error {
	k := datastore.NameKey("ScheduledConnector", uuid, nil)
	k.Namespace = updator.Site()

	if err := am.client.Delete(am.ctx, k); err != nil {
		return err
	}

	return nil
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

// Changes found when copying a into b
func SyncKeyValueList(fieldName string, a, b *[]*KeyValue, bulk EntityAuditLogCollection) bool {
	updated := false
	if fieldName != "" {
		fieldName = fieldName + "."
	}

	// Look for added items
	adds := []*KeyValue{}
	for _, x := range *a {
		var found *KeyValue = nil
		for _, y := range *b {
			if x.Key == y.Key {
				found = x
				break
			}
		}
		if found == nil {
			// a has an extra item, to add it to b
			if x.Value != "" {
				bulk.AddItem(fieldName+x.Key, "", x.Value)
				adds = append(adds, x)
				updated = true
			}
		}
	}
	for _, add := range adds {
		*b = append(*b, add)
	}

	// Look for removed items
	for _, x := range *b {
		var found *KeyValue = nil
		for _, y := range *a {
			if y.Key == x.Key {
				found = x
			}
		}
		if found == nil {
			// a has a missing item, remove it from b
			if x.Value != "" {
				bulk.AddItem(fieldName+x.Key, x.Value, "")
				x.Value = ""
				updated = true
			}
		}
	}

	for _, _ = range *b {
		for i, v := range *b {
			if v.Value == "" {
				*b = append((*b)[0:i], (*b)[i+1:]...)
				break
			}
		}
	}

	// Look for matching items
	for _, x := range *b {
		for _, y := range *a {
			if x.Key == y.Key {
				// item is in both, compare it
				if x.Value != y.Value {
					bulk.AddItem(fieldName+x.Key, x.Value, y.Value)
					x.Value = y.Value
					updated = true
				}
			}
		}
	}

	return updated
}

func (am *GaeAccessManager) LookupIp(ip string) (IPInfo, error) {
	v, _ := am.ipCache.Get(ip)
	if v != nil {
		return v.(*GaeIPInfo), nil
	}

	k := datastore.NameKey("IP", ip, nil)
	i := &GaeIPInfo{}

	err := am.client.Get(am.ctx, k, i)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return i, nil

}

func (am *GaeAccessManager) SaveIp(ip, country, region, city, timezone, organisation string) error {
	k := datastore.NameKey("IP", ip, nil)
	now := time.Now()
	i := &GaeIPInfo{
		ip:           ip,
		country:      country,
		region:       region,
		city:         city,
		timezone:     timezone,
		organisation: organisation,
		fetched:      &now,
	}
	if _, err := am.client.Put(am.ctx, k, i); err != nil {
		return err
	}
	return nil
}

type GaeIPInfo struct {
	ip           string
	country      string
	region       string
	city         string
	timezone     string
	organisation string
	fetched      *time.Time
}

func (ip *GaeIPInfo) IP() string {
	return ip.ip
}

func (ip *GaeIPInfo) Country() string {
	return ip.country
}

func (ip *GaeIPInfo) Region() string {
	return ip.region
}

func (ip *GaeIPInfo) City() string {
	return ip.city
}

func (ip *GaeIPInfo) Timezone() string {
	return ip.timezone
}

func (ip *GaeIPInfo) Organisation() string {
	return ip.organisation
}

func (ip *GaeIPInfo) Fetched() *time.Time {
	return ip.fetched
}

func (ip *GaeIPInfo) Location() string {
	return ip.country + "," + ip.region + ", " + ip.city
}

func (p *GaeIPInfo) Load(ps []datastore.Property) error {
	for _, i := range ps {
		switch i.Name {
		case "IP":
			p.ip = i.Value.(string)
			break
		case "Country":
			p.country = i.Value.(string)
			break
		case "Region":
			p.region = i.Value.(string)
			break
		case "City":
			p.city = i.Value.(string)
			break
		case "Timezone":
			p.timezone = i.Value.(string)
			break
		case "Organisation":
			p.organisation = i.Value.(string)
			break
		case "Fetched":
			if i.Value != nil {
				t := i.Value.(time.Time)
				p.fetched = &t
			}
			break
		}
	}
	return nil
}

func (p *GaeIPInfo) Save() ([]datastore.Property, error) {
	props := []datastore.Property{
		{
			Name:  "IP",
			Value: p.ip,
		},
		{
			Name:  "Country",
			Value: p.country,
		},
		{
			Name:  "Region",
			Value: p.region,
		},
		{
			Name:  "City",
			Value: p.city,
		},
		{
			Name:  "Timezone",
			Value: p.timezone,
		},
		{
			Name:  "Organisation",
			Value: p.organisation,
		},
	}

	if p.fetched != nil {
		props = append(props, datastore.Property{Name: "Fetched", Value: p.fetched})
	}

	return props, nil
}
