package security

import (
	"time"
)

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
	UserAgent() string
	Lang() string
	Locale() *time.Location
	IsIOS() bool
	Theme() Theme
}

type Theme interface {
	Name() string
	Description() string
	CSS() string
}

type ThemeInfo struct {
	name        string
	description string
	css         string
}

func (t *ThemeInfo) Name() string {
	return t.name
}

func (t *ThemeInfo) Description() string {
	return t.description
}

func (t *ThemeInfo) CSS() string {
	return t.css
}

var themes map[string]Theme
var defaultTheme Theme

func RegisterDefaultTheme(name, description, css string) {
	defaultTheme = &ThemeInfo{
		name:        name,
		description: description,
		css:         css,
	}
}
func RegisterTheme(site, name, description, css string) {
	if themes == nil {
		themes = make(map[string]Theme)
	}
	theme := &ThemeInfo{
		name:        name,
		description: description,
		css:         css,
	}
	themes[site] = theme
}

func (s *GaeSession) Theme() Theme {
	theme := themes[s.site]
	if theme != nil {
		return theme
	}
	return defaultTheme
}

func (s *CqlSession) Theme() Theme {
	theme := themes[s.site]
	if theme != nil {
		return theme
	}
	return defaultTheme
}
