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
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/uuid"
	"github.com/zaddok/log"
)

type GaeAccessManager struct {
	client   *datastore.Client
	ctx      context.Context
	log      log.Log
	setting  Setting
	template *template.Template
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
	Site         string
	Uuid         string
	FirstName    string
	LastName     string
	Email        string
	Password     *string
	Created      int64
	LastSignin   int64
	LastSigninIP string
}

type GaeSession struct {
	Site       string
	PersonUUID string
	FirstName  string
	LastName   string
	Created    int64
	Expiry     int64
	Roles      string
}

func NewGaeAccessManager(projectId string, log log.Log) (AccessManager, error) {

	settings, client, ctx := NewGaeSetting(projectId)

	t := template.New("api")
	var err error

	if t, err = t.Parse(emailHtmlTemplates); err != nil {
		log.Error("Email Template Problem: %s", err)
	}

	return &GaeAccessManager{
		client:   client,
		ctx:      ctx,
		log:      log,
		setting:  settings,
		template: t,
	}, nil
}

func (c *GaeAccessManager) Setting() Setting {
	return c.setting
}

func (c *GaeAccessManager) Log() log.Log {
	return c.log
}

func (a *GaeAccessManager) Signup(site, first_name, last_name, email, password, ip string) (*[]string, string, error) {
	var results []string

	// Check email does not already exist
	var items []GaePerson
	q := datastore.NewQuery("Person").Filter("Site =", site).Filter("Email = ", email).Limit(1)
	_, err := a.client.GetAll(a.ctx, q, &items)
	if err != nil {
		return nil, "", err
	}
	if len(items) > 0 {
		results = append(results, "This email address already belongs to a valid user.")
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
		a.log.Error("%s Send signup confirmation mail failed: %v\n", ip, err)
		results = append(results, "Sending your signup confirmation mail failed. Please retry shortly.")
		return &results, "", errors.New(results[0])
	} else {
		a.log.Info("%s Sent signup confirmation mail to: %s\n", ip, email)
	}

	return nil, token.String(), nil

}

func (g *GaeAccessManager) Authenticate(site, email, password, ip string) (Session, string, error) {

	var items []GaePerson
	q := datastore.NewQuery("Person").Filter("Site =", site).Filter("Email = ", email).Limit(1)
	_, err := g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		g.Log().Error("Authenticate() Person lookup Error: %v", err)
		return g.GuestSession(site), "", err
	}
	if len(items) > 0 {
		if items[0].Password == nil || *items[0].Password == "" {
			g.Log().Info("Signin failed. This user account has an empty password field. Email: " + email)
			return g.GuestSession(site), "Invalid email address or password.", nil
		}

		if !VerifyPassword(*items[0].Password, password) {
			g.Log().Info("Authenticate() Signin failed. User provided password failed to match stored password.")
			return g.GuestSession(site), "Invalid email address or password.", nil
		}

		now := time.Now().Unix()
		items[0].LastSignin = now
		items[0].LastSigninIP = ip
		k := datastore.NameKey("Person", items[0].Uuid, nil)
		if _, err := g.client.Put(g.ctx, k, &items[0]); err != nil {
			g.Log().Error("Authenticate() Person update Error: %v", err)
			return g.GuestSession(site), "", err
		}

		token, err2 := g.CreateSession(site, items[0].Uuid, items[0].FirstName, items[0].LastName, ip)
		if err2 != nil {
			g.Log().Error("Authenticate() Session creation error: %v", err2)
			return g.GuestSession(site), "", err2
		}

		return &session{
			token:         token,
			site:          site,
			firstName:     items[0].FirstName,
			lastName:      items[0].LastName,
			authenticated: true,
		}, "", nil
	}

	// User lookup failed
	g.Log().Info("Signin failed. Email address %s not signed up on site %s.", email, site)
	return g.GuestSession(site), "Invalid email address or password.", nil
}

func (g *GaeAccessManager) Session(site, cookie string) (Session, error) {
	if len(cookie) > 0 {
		k := datastore.NameKey("Session", site+"|"+cookie, nil)
		i := new(GaeSession)
		err := g.client.Get(g.ctx, k, i)
		if err == datastore.ErrNoSuchEntity || i.Expiry < time.Now().Unix() {
			return g.GuestSession(site), nil
		} else if err != nil {
			return g.GuestSession(site), err
		}

		session := &session{
			token:         cookie,
			site:          site,
			firstName:     i.FirstName,
			lastName:      i.LastName,
			authenticated: true,
		}

		expiry := g.setting.GetWithDefault(site, "session.expiry", "")
		if expiry == "" {
			expiry = "3600"
			g.log.Warning("System setting \"session.expiry\" not set, defaulting to 1 hour.\n")
		}
		e, err := strconv.ParseInt(expiry, 10, 64)
		if err != nil {
			e = 3600
			g.log.Warning("System setting \"session.expiry\" is not a valid number, defaulting to 1 hour.\n")
		}

		// Check this user session hasn't hit its maximum hard limit
		maxAge := g.setting.GetInt(site, "session.max_age", 2592000)
		newExpiry := time.Now().Add(time.Second * time.Duration(e)).Unix()
		if i.Created+int64(maxAge) < newExpiry {
			g.log.Warning("User session hit \"session.max_age\".\n")
			return g.GuestSession(site), nil
		}

		// So "expires" is still in the future... Update the session expiry in the database
		if newExpiry-i.Expiry > 30 {
			g.Log().Debug("updating expiry new:  %d old: %d\n", newExpiry, i.Expiry)

			type SI struct {
				Expiry int64
			}
			si := &SI{Expiry: newExpiry}
			if _, err := g.client.Put(g.ctx, k, &si); err != nil {
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
	return &session{
		token:         "",
		site:          site,
		firstName:     "",
		lastName:      "",
		authenticated: false,
	}
}

func (g *GaeAccessManager) Invalidate(site, cookie string) (Session, error) {
	session, err := g.Session(site, cookie)

	// Delete session information

	return session, err
}

// Password must already be hashed
func (g *GaeAccessManager) AddPerson(site, firstName, lastName, email string, password *string) (string, error) {

	uuid, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	si := &GaePerson{Site: site, Uuid: uuid.String(), FirstName: firstName, LastName: lastName, Email: email, Password: password, Created: now}
	k := datastore.NameKey("Person", uuid.String(), nil)
	if _, err := g.client.Put(g.ctx, k, si); err != nil {
		g.Log().Error("AddPerson() Person storage failed. Error: %v", err)
		return "", err
	}

	return uuid.String(), nil
}

func (g *GaeAccessManager) ActivateSignup(site, token, ip string) (string, string, error) {
	// Check the token is a valid uuid
	_, err := uuid.Parse(token)
	if err != nil {
		g.Log().Error("ActivateSignup() called with invalid uuid: " + err.Error())
		return "", "Invalid account activation token", nil
	}

	// Lookup the request token for the account creation request details
	type SI struct {
		Expiry int64
		Data   string
	}
	maxAge := g.setting.GetInt(site, "activation_token.max_age", 2592000)
	k := datastore.NameKey("RequestToken", token, nil)
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
	q := datastore.NewQuery("Person").Filter("Site =", site).Filter("Email = ", i.Email).Limit(1)
	_, err = g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		g.Log().Error("ActivateSignup() email lookup failure: " + err.Error())
		return "", "Activation service failed, please try again.", err
	}
	if len(items) > 0 {
		g.Log().Error("ActivateSignup() Email address already exists: %v", err)
		return "", "Can't complete account activation, this email address has recently been activated by a different person.", nil
	}

	uuid, aerr := g.AddPerson(site, i.FirstName, i.LastName, i.Email, i.Password)
	if aerr != nil {
		g.Log().Error("addPerson() failure: " + aerr.Error())
		return "", "", aerr
	}

	token, err2 := g.CreateSession(site, uuid, i.FirstName, i.LastName, ip)
	if err2 == nil {
		return token, "", nil
	}

	g.Log().Error("addPerson() createSession() failure: " + err2.Error())
	return "", "", err2
}

func (g *GaeAccessManager) CreateSession(site string, person string, firstName string, lastName string, ip string) (string, error) {
	personUuid, perr := uuid.Parse(person)
	if perr != nil {
		return "", perr
	}

	expiry := g.setting.GetWithDefault(site, "session.expiry", "")
	if expiry == "" {
		expiry = "3600"
		g.Log().Warning("System setting \"session.expiry\" not set, defaulting to 1 hour.\n")
	}
	e, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		e = 3600
		g.Log().Warning("System setting \"session.expiry\" is not a valid number, defaulting to 1 hour.\n")
	}

	token := RandomString(32)
	now := time.Now().Unix()
	expires := e + now
	roles, err := g.personRoleString(site, person)

	if err != nil {
		return "", err
	}

	ri := &GaeSession{Site: site, PersonUUID: personUuid.String(), FirstName: firstName, LastName: lastName, Created: now, Expiry: expires, Roles: roles}
	k := datastore.NameKey("Session", site+"|"+token, nil)
	if _, err := g.client.Put(g.ctx, k, ri); err != nil {
		return "", err
	}

	tkn := token[0:len(token)/2] + "..."
	g.Log().Debug("Created session \"%s\" for user %v.", tkn, personUuid)

	return token, err
}

func (g *GaeAccessManager) personRoleString(site string, uuid string) (string, error) {
	var b bytes.Buffer

	type RI struct {
		Role     string
		Resource string
		Uid      string
	}
	var items []RI
	q := datastore.NewQuery("Role").Filter("PersonUUID =", uuid).Limit(100)
	_, err := g.client.GetAll(g.ctx, q, &items)
	if err != nil {
		return "", err
	}

	for _, i := range items {
		if b.Len() > 0 {
			b.WriteString("|")
		}
		if i.Resource != "#" {
			b.WriteString(i.Role)
			b.WriteString(":")
			b.WriteString(i.Resource)
			b.WriteString(":")
			b.WriteString(i.Uid)
		} else {
			b.WriteString(i.Role)
		}
	}

	return b.String(), err
}
