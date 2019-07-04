package security

import (
	"strings"
	"time"

	"cloud.google.com/go/datastore"
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
