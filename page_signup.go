package security

import (
	"html/template"
	"net/http"
	"net/mail"
	"strings"
)

type SignupPageData struct {
	SiteName        string
	SiteDescription string
	SigninEmail     string
	FirstName       string
	LastName        string
	Email           string
	Password        string
	Password2       string
	Referer         string
	AllowSignup     bool
	Errors          []string
	Infos           []string
	Successes       []string
}

func SignupPage(t *template.Template, am AccessManager, siteName, siteDescription string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)
		am.Log().Debug("Singup page")
		session, err := LookupSession(r, am)
		if err != nil {
			am.Log().Notice("Error fetching session data %s", err)
			w.Write([]byte("Error fetching session data"))
			return
		}

		if session.IsAuthenticated() {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

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
		selfSignup := strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no"))
		if selfSignup != "yes" && selfSignup != "no" {
			selfSignup = "no"
			am.Setting().Put(HostFromRequest(r), "self.signup", selfSignup)
			am.Log().Warning("Setting default self.signup setting to no on host %s", HostFromRequest(r))
		}
		p.AllowSignup = !(strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no")) == "no")

		signupRequested := len(r.FormValue("signup")) > 0 || len(r.FormValue("register_firstname")) > 0
		var signupMessage []string

		if signupRequested {
			if len(p.FirstName) < 1 {
				signupMessage = append(signupMessage, "Please specify your first name.")
			}
			if len(p.FirstName) > 100 {
				signupMessage = append(signupMessage, "First name must be less than 100 characters.")
			}
			if len(p.LastName) < 1 {
				signupMessage = append(signupMessage, "Please specify your last name.")
			}
			if len(p.LastName) > 100 {
				signupMessage = append(signupMessage, "Last name must be less than 100 characters.")
			}
			if len(p.Email) < 1 {
				signupMessage = append(signupMessage, "Please specify your email address.")
			} else {
				_, perr := mail.ParseAddress(p.Email)
				if perr != nil {
					signupMessage = append(signupMessage, "Please specify a valid email address.")
				}
			}
			if len(p.Email) > 255 {
				signupMessage = append(signupMessage, "Email address must be less than 250 characters.")
			}
			//if !p.TermsAndConditions {
			//	signupMessage = append(signupMessage, "Please confirm you agree with the terms and conditions.")
			//}
			if len(p.Password) < 1 {
				signupMessage = append(signupMessage, "Please specify your desired password.")
			} else if len(p.Password) < 6 {
				signupMessage = append(signupMessage, "Please specify a password with at least 6 characters.")
			} else if len(p.Password) > 200 {
				signupMessage = append(signupMessage, "Password must be less than 200 characters.")
			} else if len(p.Password2) < 1 {
				signupMessage = append(signupMessage, "Please re-enter your password.")
			} else if p.Password != p.Password2 {
				signupMessage = append(signupMessage, "You typed your password twice, but they do not match.")
			}
			if len(signupMessage) > 0 {
				p.Errors = signupMessage
			} else {
				ip := IpFromRequest(r)
				errors, _, err := am.Signup(HostFromRequest(r), p.FirstName, p.LastName, p.Email, p.Password, ip)
				if errors != nil {
					p.Errors = *errors
				} else if err != nil {
					p.Errors = append(p.Errors, err.Error())
				} else {
					p.Successes = append(p.Successes, "To complete your sign up, please check your email for instructions on how to verify your email address.")
					p.FirstName = ""
					p.LastName = ""
					p.Email = ""
					p.Password = ""
					p.Password2 = ""
				}
			}
		}

		err = t.ExecuteTemplate(w, "signin_page", p)
		if err != nil {
			am.Log().Notice("Error displaying 'signup' page: %v", err)
			w.Write([]byte("Error displaying 'signup' page"))
			return
		}
	}
}
