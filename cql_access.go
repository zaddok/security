package security

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/gocql/gocql"

	"github.com/zaddok/log"
)

type CqlAccessManager struct {
	cql           *gocql.Session
	log           log.Log
	setting       Setting
	picklistStore PicklistStore
	template      *template.Template
}

func NewCqlAccessManager(cql *gocql.Session, log log.Log) (AccessManager, error) {

	settings := NewCqlSetting(cql)

	t := template.New("api")
	var err error

	if t, err = t.Parse(emailHtmlTemplates); err != nil {
		log.Error("Email Template Problem: %s", err)
	}

	// Dump out settings for debug purposes
	/*
		rows := cql.Query("select site, name, value from setting").Iter()
		var site string
		var name string
		var value string
		fmt.Println("Settings")
		for rows.Scan(&site, &name, &value) {
			fmt.Printf("    %s: %s = %s\n", site, strings.ToLower(name), value)
		}
		err = rows.Close()

		if err != nil {
			log.Error("Error reading settings from cassandra: %v", err)
			return nil, errors.New(fmt.Sprintf("Error reading settings from cassandra: %v", err))
		}
	*/

	return &CqlAccessManager{
		cql:           cql,
		log:           log,
		setting:       settings,
		picklistStore: nil, //TODO
		template:      t,
	}, nil
}

func (c *CqlAccessManager) Setting() Setting {
	return c.setting
}

func (c *CqlAccessManager) PicklistStore() PicklistStore {
	return c.picklistStore
}

func (c *CqlAccessManager) Log() log.Log {
	return c.log
}

func (a *CqlAccessManager) Signup(site, first_name, last_name, email, password, ip string) (*[]string, string, error) {
	var results []string

	// Check email does not already exist
	var e string
	i := a.cql.Query("select email from person where site = ? and email = ?", site, email).Iter()
	match := i.Scan(&e)
	if match {
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

	token := gocql.TimeUUID()
	a.log.Info("%s Sign up confirmation token for \"%s\" is \"%s\"", ip, email, token.String())

	//TODO: expiry time set to actual desired expiry time
	rows := a.cql.Query("insert into request_token (uid, person_uuid, type, ip, expiry, data) values(?,?,'signup_confirmation',?,?,?)",
		token.String(), token, ip, time.Now().Unix(), data).Iter()
	err := rows.Close()
	if err != nil {
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

func (a *CqlAccessManager) ForgotPasswordRequest(site, email, ip string) (string, error) {

	var actualPassword string
	var firstName string
	var lastName string
	var uuid gocql.UUID
	i := a.cql.Query("select uuid, password, first_name, last_name from person where site=? and email=?", site, email).Iter()
	if i.Scan(&uuid, &actualPassword, &firstName, &lastName) {
		if actualPassword == "" {
			a.Log().Info("Forgot Password Request ignored for account with an empty password field. Email: " + email)
			return "", nil
		}
		// Found email address and it is valid, so lets send an email

		return "", errors.New("Unimplemented")
	}

	a.Log().Info("Forgot Password Request ignored for unknown email address: " + email)
	return "", nil
}

func (g *CqlAccessManager) Authenticate(site, email, password, ip string) (Session, string, error) {

	var actualPassword string
	var firstName string
	var lastName string
	var uuid gocql.UUID
	i := g.cql.Query("select uuid, password, first_name, last_name from person where site=? and email=?", site, email).Iter()
	if i.Scan(&uuid, &actualPassword, &firstName, &lastName) {

		if actualPassword == "" {
			g.Log().Info("Signin failed. This user account has an empty password field. Email: " + email)
			return g.GuestSession(site), "Invalid email address or password.", nil
		}

		if !VerifyPassword(actualPassword, password) {
			g.Log().Info("Authenticate() Signin failed. User provided password failes to match stored password.")
			return g.GuestSession(site), "Invalid email address or password.", nil
		}

		uerr := g.cql.Query("update person set last_auth=?,last_auth_ip=? where site=? and uuid=?", time.Now().Unix(), ip, site, uuid).Exec()
		if uerr != nil {
			g.Log().Error("Authenticate() Person update Error: %v", uerr)
			return g.GuestSession(site), "", uerr
		}

		token, err2 := g.CreateSession(site, uuid.String(), firstName, lastName, email, ip)
		if err2 != nil {
			g.Log().Error("Authenticate() Session creation error: %v", err2)
			return g.GuestSession(site), "", err2
		}

		i.Close()
		return &CqlSession{
			Token:         token,
			Site:          site,
			FirstName:     firstName,
			LastName:      lastName,
			Email:         email,
			Authenticated: true,
		}, "", nil
	}

	err := i.Close()
	if err != nil {
		g.Log().Error("Authenticate() Person lookup Error: %v", err)
		return g.GuestSession(site), "", err
	}

	// User lookup failed
	g.Log().Info("Signin failed. Email address %s not signed up on site %s.", email, site)
	return g.GuestSession(site), "Invalid email address or password.", nil
}

func (g *CqlAccessManager) GetPersonByFirstNameLastName(site, firstname, lastname string) (Person, error) {
	return nil, errors.New("unimplemented")
}

// Request the session information associated the site hostname and cookie in the web request
func (g *CqlAccessManager) GetSystemSession(site, firstname, lastname string) (Session, error) {
	return nil, errors.New("unimplemented")
}

func (g *CqlAccessManager) Session(site, cookie string) (Session, error) {
	if len(cookie) > 0 {
		rows := g.cql.Query("select first_name, last_name, person_uuid, created, expiry, roles, email from session_token where site=? and uid=?", site, cookie).Iter()

		var created int64
		var expires int64
		var uuid gocql.UUID
		var firstName, lastName, roles, email string
		match := rows.Scan(&firstName, &lastName, &uuid, &created, &expires, &roles, &email)
		err := rows.Close()
		if err != nil {
			return g.GuestSession(site), err
		}

		if !match || expires < time.Now().Unix() {
			return g.GuestSession(site), nil
		}
		//user.Id = &uuid
		session := &CqlSession{
			Token:         cookie,
			Site:          site,
			FirstName:     firstName,
			LastName:      lastName,
			Email:         email,
			Authenticated: true,
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
		if created+int64(maxAge) < newExpiry {
			g.log.Warning("User session hit \"session.max_age\".\n")
			return g.GuestSession(site), nil
		}

		// So "expires" is still in the future... Update the session expiry in the database
		if newExpiry-expires > 30 {
			fmt.Printf("updating expiry new:  %d old: %d\n", newExpiry, expires)
			err = g.cql.Query("update session_token set expiry=? where site=? and uid=?", newExpiry, site, cookie).Exec()
		} else {
			//fmt.Println("not updating expiry")
		}

		return session, nil
	}

	g.log.Debug("Session() no valid cookie")

	return g.GuestSession(site), nil
}

func (g *CqlAccessManager) GuestSession(site string) Session {
	return &CqlSession{
		Token:         "",
		Site:          site,
		FirstName:     "",
		LastName:      "",
		Email:         "",
		Authenticated: false,
	}
}

func (g *CqlAccessManager) Invalidate(site, cookie string) (Session, error) {
	session, err := g.Session(site, cookie)

	// Delete session information

	return session, err
}

func (g *CqlAccessManager) AddPerson(site, firstName, lastName, email string, password *string) (string, error) {

	uuid := gocql.TimeUUID()
	rows := g.cql.Query("insert into person (site, uuid, first_name, last_name, email, password, created) values(?,?,?,?,?,?,?)",
		site, uuid, firstName, lastName, email, password, NowMilliseconds()).Iter()
	err := rows.Close()
	if err != nil {
		return "", err
	}

	rows = g.cql.Query("update general_counter set total = total + 1 where name='public.person.count'").Iter()
	rows.Close()

	return uuid.String(), nil
}

func (g *CqlAccessManager) ActivateSignup(site, token, ip string) (string, string, error) {
	uuid, err := gocql.ParseUUID(token)
	if err != nil {
		return "", "Invalid account activation token", nil
	}

	// Look up the details of the person this message is for
	var data string
	i := g.cql.Query("select data from request_token where uid=?", uuid.String()).Iter()
	match := i.Scan(&data)
	if match {
		i := &NewUserInfo{}
		json.Unmarshal([]byte(data), i)

		// Check another account sign up has not just occured using this same email address
		var e string
		pc := g.cql.Query("select email from person where site = ? and email = ?", site, i.Email).Iter()
		defer pc.Close()
		match := pc.Scan(&e)
		if match {
			return "", "Can't complete account activation, this email address has recently been activated by a different person.", nil
		} else {

			uuid, aerr := g.AddPerson(site, i.FirstName, i.LastName, i.Email, i.Password)

			if aerr == nil {
				token, err2 := g.CreateSession(site, uuid, i.FirstName, i.LastName, i.Email, ip)
				if err2 == nil {
					return token, "", nil
				} else {
					g.Log().Error("addPerson() createSession() failure: " + err2.Error())
					return "", "", err2
				}
			} else {
				g.Log().Error("addPerson() failure: " + aerr.Error())
				return "", "", aerr
			}
		}

	}

	return "", "Invalid activation token", nil
}

func (g *CqlAccessManager) CreateSession(site string, person string, firstName string, lastName string, email string, ip string) (string, error) {
	personUuid, perr := gocql.ParseUUID(person)
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
	roles, err := cqlPersonRoleString(g.cql, site, person)

	if err != nil {
		return "", err
	}

	err = g.cql.Query(
		"insert into session_token (site, person_uuid, uid, roles, expiry, created, first_name, last_name, email) "+
			"values(?,?,?,?,?,?,?,?,?)",
		site, personUuid, token, roles, expires, now, firstName, lastName, email).Exec()
	if err != nil {
		return "", err
	}

	tkn := token[0:len(token)/2] + "..."
	g.Log().Debug("Created session \"%s\" for user %v.", tkn, personUuid)

	return token, err
}

func cqlPersonRoleString(cql *gocql.Session, site string, uuid string) (string, error) {
	var role string
	var resource string
	var uid string
	var b bytes.Buffer

	//TODO: Fix cql allow filtering
	i := cql.Query("select role, resource, uid from role where person_uuid=? allow filtering", uuid).Iter()
	for i.Scan(&role, &resource, &uid) {
		if b.Len() > 0 {
			b.WriteString("|")
		}
		if resource != "#" {
			b.WriteString(role)
			b.WriteString(":")
			b.WriteString(resource)
			b.WriteString(":")
			b.WriteString(uid)
		} else {
			b.WriteString(role)
		}
	}
	err := i.Close()

	return b.String(), err
}

func (am *CqlAccessManager) WipeDatastore(namespace string) error {
	return errors.New("Unimeplemented")
}

type CqlSession struct {
	PersonUUID    string
	FirstName     string
	LastName      string
	Email         string
	Created       int64
	Expiry        int64
	Roles         string
	Authenticated bool
	Token         string
	Site          string
}

func (s *CqlSession) GetPersonUuid() string {
	return s.PersonUUID
}

func (s *CqlSession) GetToken() string {
	return s.Token
}

func (s *CqlSession) GetSite() string {
	return s.Site
}

func (s *CqlSession) GetFirstName() string {
	return s.FirstName
}

func (s *CqlSession) GetLastName() string {
	return s.LastName
}

func (s *CqlSession) GetEmail() string {
	return s.Email
}

func (s *CqlSession) IsAuthenticated() bool {
	return s.Authenticated
}
