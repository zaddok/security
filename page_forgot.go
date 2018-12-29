package security

import (
	"html/template"
	"net/http"
)

func ForgotPage(t *template.Template, am AccessManager, siteName, siteDescription string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)
		am.Log().Debug("Forgot password page")

		_, err := LookupSession(r, am)
		if err != nil {
			am.Log().Notice("Error fetching session data %s", err)
			w.Write([]byte("Error fetching session data"))
			return
		}

		type Page struct {
			SiteName    string
			SigninEmail string
			Errors      []string
			Infos       []string
			Successes   []string
		}
		p := &Page{}
		p.SiteName = siteName

		if r.FormValue("signin_email") != "" {
			p.Infos = append(p.Infos, "If this email address is in our system, you should receive an email shortly with a password reset link.")
		}

		err = t.ExecuteTemplate(w, "forgot_password_page", p)
		if err != nil {
			am.Log().Notice("Error displaying 'forgot' page: %v", err)
			w.Write([]byte("Error displaying 'forgot' page"))
			return
		}
	}
}
