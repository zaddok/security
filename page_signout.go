package security

import (
	"html/template"
	"net/http"
	"time"
)

func SignoutPage(t *template.Template, am AccessManager, siteName, siteDescription string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)
		session, err := LookupSession(r, am)

		_, err = am.Invalidate(session.Site(), session.IP(), session.Token())
		if err != nil {
			am.Notice(session, `auth`, "Error invalidating session on 'signout' page: %v", err)
			w.Write([]byte("Error displaying 'signout' page"))
			return
		}

		// wipe cookie
		cookie := &http.Cookie{
			Name:     "z",
			Value:    session.Token(),
			Path:     "/",
			Expires:  time.Now().Add(time.Minute * 60 * 24 * -356),
			Secure:   false,
			HttpOnly: true,
			MaxAge:   0,
		}
		http.SetCookie(w, cookie)
		if err != nil && session != nil {
			am.Notice(session, `auth`, "Signout from %s (%s)", session.DisplayName(), session.Email())
		}
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}
