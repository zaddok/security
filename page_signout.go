package security

import (
	"html/template"
	"net/http"
	"time"
)

func SignoutPage(t *template.Template, am AccessManager, siteName, siteDescription string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)
		session, err := am.Invalidate("cookie", HostFromRequest(r))
		if err != nil {
			am.Log().Notice("Error displaying 'signout' page: %v", err)
			w.Write([]byte("Error displaying 'signout' page"))
			return
		}

		// wipe cookie
		cookie := &http.Cookie{
			Name:     "z",
			Value:    session.GetToken(),
			Path:     "/",
			Expires:  time.Now().Add(time.Minute * 60 * 24 * -356),
			Secure:   false,
			HttpOnly: true,
			MaxAge:   0,
		}
		http.SetCookie(w, cookie)
		if err != nil && session != nil && session.IsAuthenticated() {
			am.Log().Info("Signout from %s %s", session.GetFirstName(), session.GetLastName())
		}
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}
