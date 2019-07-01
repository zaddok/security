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

		if session.IsAuthenticated() {
			_, err = am.Invalidate(session.Site(), session.IP(), session.Token(), session.UserAgent(), session.Lang())
			if err != nil {
				am.Notice(session, `auth`, "Error invalidating session on 'signout' page. Token=%s: %v", session.Token, err)
				w.Write([]byte("Error processing signout request"))
				return
			}
			if session != nil {
				am.Notice(session, `auth`, "Signout from %s (%s)", session.DisplayName(), session.Email())
			}
		}
		if session.Token() != "" {
			am.Debug(session, `auth`, "Signout called without cookie set")
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
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}
