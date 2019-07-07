package security

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/uuid"
)

type GaeSession struct {
	ip            string
	personUUID    string
	firstName     string
	lastName      string
	email         string
	created       *time.Time
	expiry        *time.Time
	authenticated bool
	csrf          string
	roles         string
	userAgent     string
	lang          string
	locale        *time.Location

	site    string          `datastore:"-"`
	token   string          `datastore:"-"`
	roleMap map[string]bool `datastore:"-"`
}

func (s *GaeSession) IP() string {
	return s.ip
}

func (s *GaeSession) PersonUuid() string {
	return s.personUUID
}

func (s *GaeSession) Token() string {
	return s.token
}

func (s *GaeSession) Created() *time.Time {
	return s.created
}

func (s *GaeSession) Expiry() *time.Time {
	return s.expiry
}

func (s *GaeSession) CSRF() string {
	return s.csrf
}

func (s *GaeSession) Site() string {
	return s.site
}

func (s *GaeSession) FirstName() string {
	return s.firstName
}

func (s *GaeSession) LastName() string {
	return s.lastName
}

func (s *GaeSession) DisplayName() string {
	return s.firstName + " " + s.lastName
}

func (s *GaeSession) Email() string {
	return s.email
}

func (s *GaeSession) UserAgent() string {
	return s.userAgent
}

func (s *GaeSession) Locale() *time.Location {
	return s.locale
}

func (s *GaeSession) Lang() string {
	return s.lang
}

func (s *GaeSession) IsIOS() bool {
	if strings.Index(s.userAgent, "iPhone") > 0 {
		return true
	}
	if strings.Index(s.userAgent, "iPad") > 0 {
		return true
	}
	return false
}

func (s *GaeSession) IsAuthenticated() bool {
	return s.authenticated
}

func (s *GaeSession) HasRole(uid string) bool {
	if s.roleMap == nil {
		s.roleMap = make(map[string]bool)
		for _, v := range strings.FieldsFunc(s.roles, func(c rune) bool { return c == ':' }) {
			s.roleMap[v] = true
		}
	}

	_, found := s.roleMap[uid]
	return found
}

func (p *GaeSession) Load(ps []datastore.Property) error {
	for _, i := range ps {
		switch i.Name {
		case "PersonUUID":
			p.personUUID = i.Value.(string)
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
		case "Authenticated":
			p.authenticated = i.Value.(bool)
			break
		case "IP":
			p.ip = i.Value.(string)
			break
		case "CSRF":
			p.csrf = i.Value.(string)
			break
		case "Roles":
			p.roles = i.Value.(string)
			break
		case "Site":
			p.site = i.Value.(string)
			break
		case "Created":
			if i.Value != nil {
				t := i.Value.(time.Time)
				p.created = &t
			}
			break
		case "Expiry":
			if i.Value != nil {
				t := i.Value.(time.Time)
				p.expiry = &t
			}
			break
		}
	}
	return nil
}

func (p *GaeSession) Save() ([]datastore.Property, error) {
	props := []datastore.Property{
		{
			Name:  "PersonUUID",
			Value: p.personUUID,
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
			Name:  "Authenticated",
			Value: p.authenticated,
		},
		{
			Name:  "CSRF",
			Value: p.csrf,
		},
		{
			Name:  "IP",
			Value: p.ip,
		},
	}

	if p.roles != "" {
		props = append(props, datastore.Property{Name: "Roles", Value: p.roles})
	}
	if p.created != nil {
		props = append(props, datastore.Property{Name: "Created", Value: p.created})
	}
	if p.expiry != nil {
		props = append(props, datastore.Property{Name: "Expiry", Value: p.expiry})
	}

	return props, nil
}

func (g *GaeAccessManager) createSession(site, person, firstName, lastName, email, roles, ip string) (string, error) {
	personUuid, perr := uuid.Parse(person)
	if perr != nil {
		return "", perr
	}

	// NOTE: If the datastore fails, reading this setting will fail, resulting in an update to a defult seting.
	expiry := g.setting.GetWithDefault(site, "session.expiry", "")
	if expiry == "" {
		expiry = "3600"
		g.setting.Put(site, `session.expiry`, `3600`)
	}
	e, err := strconv.Atoi(expiry)
	if err != nil {
		e = 3600
		// If parsing a valid setting failed, it is not a valid number, reset to default
		if expiry != "" {
			g.setting.Put(site, `session.expiry`, `3600`)
		}
	}

	token := RandomString(32)
	now := time.Now()
	expires := now.Add(time.Duration(e) * time.Second)

	if err != nil {
		return "", err
	}

	session := &GaeSession{
		site:          site,
		ip:            ip,
		personUUID:    personUuid.String(),
		token:         token,
		firstName:     firstName,
		lastName:      lastName,
		email:         email,
		created:       &now,
		expiry:        &expires,
		roles:         roles,
		authenticated: true,
		roleMap:       nil,
		csrf:          RandomString(8),
	}

	k := datastore.NameKey("Session", token, nil)
	k.Namespace = site
	if _, err := g.client.Put(g.ctx, k, session); err != nil {
		return "", err
	}
	g.sessionCache.Set(token, session)

	//tkn := token[0:len(token)/2] + "..."
	//g.Log().Debug("Created session \"%s\" for user %v.", tkn, personUuid)

	return token, err
}

// Request the session information associated the site hostname and cookie in the web request
func (g *GaeAccessManager) Session(site, ip, cookie, userAgent, lang string) (Session, error) {
	if len(cookie) > 0 {
		k := datastore.NameKey("Session", cookie, nil)
		k.Namespace = site

		// Lookup session from cache if possible
		var session *GaeSession
		v, _ := g.sessionCache.Get(cookie)
		if v != nil {
			session = v.(*GaeSession)
			// Fill the transient/non-persisted fields
			session.userAgent = userAgent
			session.lang = lang
			session.locale = g.defaultLocale
			session.site = site
			if session.ip != ip {
				g.Debug(session, `auth`, "Session IP for %s moving fom %s to %s", session.DisplayName(), session.ip, ip)
				session.ip = ip
			}
		} else {
			session = new(GaeSession)
			err := g.client.Get(g.ctx, k, session)
			if err == datastore.ErrNoSuchEntity {
				return g.GuestSession(site, ip, userAgent, lang), nil
			} else if err != nil {
				return g.GuestSession(site, ip, userAgent, lang), err
			}

			// Fill the transient/non-persisted fields
			session.token = cookie
			session.site = site
			session.roleMap = nil
			session.ip = ip
			session.userAgent = userAgent
			session.lang = lang
			session.locale = g.defaultLocale

			if session.ip != ip {
				g.Debug(session, `auth`, "Session IP for %s moving fom %s to %s", session.DisplayName(), session.ip, ip)
				session.ip = ip
			}

			g.sessionCache.Set(cookie, session)
		}

		if session.expiry.Before(time.Now()) {
			g.Debug(session, `auth`, "Session expired for %s: %v", session.DisplayName(), session.expiry)
			g.client.Delete(g.ctx, k)
			g.sessionCache.Remove(cookie)
			return g.GuestSession(site, ip, userAgent, lang), nil
		}

		expiry := g.setting.GetInt(site, `session.expiry`, 0)
		if expiry == 0 {
			expiry = 3600
			g.setting.Put(site, `session.expiry`, strconv.Itoa(expiry))
		}

		// Check this user session hasn't hit its maximum hard limit
		maxAge := g.setting.GetInt(site, "session.max_age", 0)
		if maxAge == 0 {
			maxAge = 2592000
			g.setting.Put(site, "session.max_age", strconv.Itoa(maxAge))
		}
		newExpiry := time.Now().Add(time.Second * time.Duration(expiry))
		if session.Created().Add(time.Duration(maxAge) * time.Second).Before(time.Now()) {
			g.Warning(session, `auth`, "Session for %s hit \"session.max_age\". Session created: %v Max Age: %v", session.DisplayName(), session.Created(), session.Created().Add(time.Duration(maxAge)*time.Second))
			g.client.Delete(g.ctx, k)
			g.sessionCache.Remove(cookie)
			return g.GuestSession(site, ip, userAgent, lang), nil
		}

		// So "expires" is still in the future... Update the session expiry in the database
		if newExpiry.Unix()-session.Expiry().Unix() > 30 {
			//g.Log().Debug("updating expiry new:  %d old: %d", newExpiry, i.Expiry)

			session.expiry = &newExpiry
			if _, err := g.client.Put(g.ctx, k, session); err != nil {
				g.Error(session, `datastore`, "Session() Session expiry update failed: %v", err)
				return session, nil
			}
		} else {
			// Session expiry field will only be updated every 30 seconds
			// No need to hit the databbase with a session update upon every single page load
		}

		return session, nil
	}

	//g.Debug("Session() no valid cookie")

	return g.GuestSession(site, ip, userAgent, lang), nil
}

func (g *GaeAccessManager) GuestSession(site, ip, userAgent, lang string) Session {
	return &GaeSession{
		site:          site,
		ip:            ip,
		token:         "",
		firstName:     "",
		lastName:      "",
		authenticated: false,
		roles:         "",
		csrf:          "",
		roleMap:       make(map[string]bool),
		userAgent:     userAgent,
		lang:          lang,
		locale:        g.defaultLocale,
	}
}

// Invalidate removes session information from the datastore. Alternate behaviour
// might be to simply flag session as unauthenticated.
func (g *GaeAccessManager) Invalidate(site, ip, cookie, userAgent, lang string) (Session, error) {
	if cookie == "" {
		session := g.GuestSession(site, ip, userAgent, lang)
		g.Debug(session, `datastore`, "Invalidate called with empty cookie")
		return session, nil
	}

	session, err := g.Session(site, ip, cookie, userAgent, lang)

	// Delete session information
	g.sessionCache.Remove(cookie)

	k := datastore.NameKey("Session", cookie, nil)
	k.Namespace = site
	err = g.client.Delete(g.ctx, k)
	if err != nil {
		g.Error(session, `auth`, "Signout for %s failed. %v", session.DisplayName(), err)
		return session, err
	}
	g.Info(session, `auth`, "Signout by %v (%s)", session.DisplayName(), session.Email())

	return session, err
}
