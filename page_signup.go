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
	SupplimentalCss string
	FirstName       string
	LastName        string
	Email           string
	Password        string
	Password2       string
	Referer         string
	AllowSignup     bool
	Session         Session
	Errors          []string
	Infos           []string
	Successes       []string
}

func SignupPage(t *template.Template, am AccessManager, siteName, siteDescription, supplimentalCss string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)

		session, err := LookupSession(r, am)
		if err != nil {
			am.Notice(session, `http`, "Error fetching session data %s", err)
			w.Write([]byte("Error fetching session data"))
			return
		}

		FirstRequestOnSite(session.Site(), am)

		if session.IsAuthenticated() {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		p := &SignupPageData{}
		p.SiteName = siteName
		p.SiteDescription = siteDescription
		p.SupplimentalCss = supplimentalCss
		p.FirstName = strings.TrimSpace(r.FormValue("first_name"))
		p.LastName = strings.TrimSpace(r.FormValue("last_name"))
		p.Email = strings.TrimSpace(r.FormValue("email"))
		p.Password = strings.TrimSpace(r.FormValue("password"))
		p.Password2 = strings.TrimSpace(r.FormValue("password2"))
		p.Session = session
		if r.FormValue("r") != "" {
			p.Referer = r.FormValue("r")
		}
		//p.TermsAndConditions = len(strings.TrimSpace(r.FormValue("terms_and_conditions"))) > 0 ||
		//	len(strings.TrimSpace(r.FormValue("i_agree"))) > 0
		selfSignup := strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no"))
		if selfSignup != "yes" && selfSignup != "no" {
			selfSignup = "no"
			am.Setting().Put(HostFromRequest(r), "self.signup", selfSignup)
			am.Warning(session, `security`, "Setting default self.signup setting to no on host %s", HostFromRequest(r))
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
			} else if len(p.Password) > 100 {
				signupMessage = append(signupMessage, "Password must be less than 100 characters.")
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
			am.Notice(session, `html`, "Error displaying 'signup' page: %v", err)
			w.Write([]byte("Error displaying 'signup' page"))
			return
		}
	}
}

var SignupTemplate = `
{{define "signin_page"}}
{{template "security_header" .}}

{{if .Successes}}<div class="feedback success">{{if eq 1 (len .Successes)}}<p>{{index .Successes 0}}</p>{{else}}<ul>{{range .Successes}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Errors}}<div class="feedback error">{{if eq 1 (len .Errors)}}<p>{{index .Errors 0}}</p>{{else}}<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Infos}}<div class="feedback info">{{if eq 1 (len .Infos) }}<p>{{index .Infos 0}}</p>{{else}}<ul>{{range .Infos}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="signin_box">

<div id="site_banner">
	<h2>{{.SiteName}}</h2>
</div>

<form method="post" action="/signin" id="signin">
<input type="hidden" name="r" value="{{.Referer}}">
<h3>Sign in</h3>

<label for="signin_username">
<input type="email" name="signin_email" id="signin_email" value='{{.SigninEmail}}' placeholder="Email address"/>
</label>

<label for="signin_password">
<input type="password" name="signin_password" id="signin_password" value="{{.Password}}" placeholder="Password"/></span>
<p class="forgot"><a href="/forgot/">Forgot your password?</a></p>

	<input type="submit" name="signin" value="Sign in"/>
</label>



</form>


</div>

{{if .AllowSignup}}
<div id="signup_box">

<form method="post" action="/signup" id="signup">
<h3>Sign up</h3>

<label for="firstname">
<input type="text" placeholder="First name" name="first_name" id="first_name" value='{{.FirstName}}'/>
</label>

<label for="lastname">
<input type="text" placeholder="Last name" name="last_name" id="last_name" value='{{.LastName}}'/>
</label>

<label for="email">
<input type="text" placeholder="Email address" name="email" id="email" value='{{.Email}}'/>
</label>

<label for="password">
<input type="password" placeholder="Password" name="password" id="password" autocomplete="off" value="{{.Password}}"/>
</label>

<label for="password2">
<input type="password" placeholder="Re-type password" name="password2" id="password2" value="{{.Password2}}"/>
</label>

<p>By signing up, you agree that you have read and accepted our <a href="/user.agreement">User Agreement</a>, you consent to our <a href="/privacy">Privacy Notice</a> and receiving email that may contain marketing communications from us.</p>

<div class="submit">
<input type="submit" name="signup" value="Sign up"/>
 </div>

</form>
</div>
{{end}}

<script type="text/javascript">
if(document.getElementById('signin_email').value!="") {
	 document.getElementById('signin_password').focus();
} else {
	document.getElementById('signin_email').focus();
}
</script>

{{template "security_footer" .}}
{{end}}
`
