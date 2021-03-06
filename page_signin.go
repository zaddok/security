package security

import (
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"
)

func SigninPage(t *template.Template, am AccessManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := LookupSession(r, am)
		if err != nil {
			ShowError(w, r, t, err, session)
			return
		}

		// HTTP GET to the signin page should return the full signin/signup page
		if r.Method != "POST" {
			SignupPage(t, am)(w, r)
			return
		}

		AddSafeHeaders(w)

		ip := IpFromRequest(r)
		session, failure, err := am.Authenticate(HostFromRequest(r), r.FormValue("signin_email"), r.FormValue("signin_password"), ip, session.UserAgent(), session.Lang())
		if err != nil {
			am.Error(session, `auth`, "Error during authentication: %v", err)
			ShowError(w, r, t, errors.New("An error occurred, please try again shortly."), session)
			return
		}
		if failure != "" || session == nil {
			session, err := LookupSession(r, am)

			p := &SignupPageData{}
			p.Session = session
			p.Title = []string{"Signin"}
			p.Class = "signin"
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
				am.Notice(session, `html`, "Error displaying 'signin_page': %v", err)
				w.Write([]byte("Error displaying 'signin_page' page"))
				return
			}
			return
		}

		// Signin successful
		refer := r.FormValue("r")
		if strings.Index(refer, "://") >= 0 {
			am.Notice(session, `auth`, "Signin with invalid referrer URL: %v", refer)
			refer = ""
		}
		if strings.Index(refer, "?") >= 0 {
			am.Notice(session, `auth`, "Signin with invalid referrer URL: %v", refer)
			refer = refer[0:strings.Index(refer, "?")]
			am.Notice(session, `auth`, "Invalid referrer URL trimmed to: %v", refer)
		}

		if refer != "" && refer[0] != '/' {
			refer = "/" + refer
		}

		cookie := &http.Cookie{
			Name:     "z",
			Value:    session.Token(),
			Path:     "/",
			Secure:   false,
			HttpOnly: true,
			Expires:  time.Now().Add(time.Minute * 60 * 24 * time.Duration(COOKIE_DAYS)),
			MaxAge:   60 * 60 * 24 * COOKIE_DAYS,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, refer, http.StatusSeeOther)
	}
}
