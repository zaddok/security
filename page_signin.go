package security

import (
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"
)

func SigninPage(t *template.Template, am AccessManager, siteName, siteDescription string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)

		ip := IpFromRequest(r)
		session, failure, err := am.Authenticate(HostFromRequest(r), r.FormValue("signin_email"), r.FormValue("signin_password"), ip)
		if err != nil {
			am.Log().Error("Error during authentication: %s", err)
			ShowError(w, r, t, errors.New("An error occurred, please try again shortly."), siteName)

			//http.Redirect(w, r, "/?e=f", http.StatusTemporaryRedirect)
			return
		}
		if failure != "" || session == nil {
			am.Log().Error("Error during authentication: %s %s", failure, err)
			//http.Redirect(w, r, "/?e=f", http.StatusTemporaryRedirect)
			//return

			p := &SignupPageData{}
			p.SiteName = siteName
			p.SiteDescription = siteDescription
			p.FirstName = strings.TrimSpace(r.FormValue("first_name"))
			p.LastName = strings.TrimSpace(r.FormValue("last_name"))
			p.Email = strings.TrimSpace(r.FormValue("email"))
			p.Password = strings.TrimSpace(r.FormValue("password"))
			p.Password2 = strings.TrimSpace(r.FormValue("password2"))
			if r.FormValue("r") != "" {
				p.Referer = r.FormValue("r")
			}
			//p.TermsAndConditions = len(strings.TrimSpace(r.FormValue("terms_and_conditions"))) > 0 ||
			//	len(strings.TrimSpace(r.FormValue("i_agree"))) > 0
			p.AllowSignup = !(strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no")) == "no")
			if failure != "" {
				p.Errors = append(p.Errors, failure)
			}
			p.AllowSignup = !(strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no")) == "no")

			err = t.ExecuteTemplate(w, "signin_page", p)
			if err != nil {
				am.Log().Notice("Error displaying 'signup' page: %v", err)
				w.Write([]byte("Error displaying 'signup' page"))
				return
			}
		}

		// Signin successful
		refer := ""
		if r.FormValue("referer") != "" {
			if strings.Index(r.FormValue("referer"), "/") < 0 {
				refer = r.FormValue("referer")
			}
		}

		cookie := &http.Cookie{
			Name:     "z",
			Value:    session.GetToken(),
			Path:     "/",
			Secure:   false,
			HttpOnly: true,
			Expires:  time.Now().Add(time.Minute * 60 * 24 * time.Duration(COOKIE_DAYS)),
			MaxAge:   60 * 60 * 24 * COOKIE_DAYS,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/"+refer+"?e=s", http.StatusTemporaryRedirect)
	}
}