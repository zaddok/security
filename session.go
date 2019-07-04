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
}
