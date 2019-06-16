package security

import (
	"fmt"
	"html/template"
	"net/http"
)

func ForgotPage(t *template.Template, am AccessManager, siteName, siteDescription, supplimentalCss string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)

		session, err := LookupSession(r, am)
		if err != nil {
			am.Notice(session, `http`, "Error fetching session data %s", err)
			w.Write([]byte("Error fetching session data"))
			return
		}

		type Page struct {
			SiteName        string
			SiteDescription string
			SigninEmail     string
			SupplimentalCss string
			Session         Session
			Errors          []string
			Infos           []string
			Successes       []string
		}
		p := &Page{}
		p.SiteName = siteName
		p.SiteDescription = siteDescription
		p.SupplimentalCss = supplimentalCss
		p.Session = session

		if r.FormValue("signin_email") != "" {
			p.Infos = append(p.Infos, "If this email address is in our system, you should receive an email shortly with a password reset link.")
		}

		err = t.ExecuteTemplate(w, "forgot_password_page", p)
		if err != nil {
			am.Notice(session, `html`, "Error displaying 'forgot' page: %v", err)
			w.Write([]byte("Error displaying 'forgot' page"))
			return
		}

		token, err := am.ForgotPasswordRequest(session.Site(), r.FormValue("signin_email"), IpFromRequest(r))
		if err != nil {
			fmt.Println("Forgot password request failed:", err)
		} else {
			fmt.Println("Forgot password request successs:", token, r.FormValue("signin_email"))
		}
	}
}

var ForgotTemplate = `
{{define "forgot_password_page"}}
{{template "security_header" .}}

{{if .Successes}}<div class="feedback success">{{if eq 1 (len .Successes)}}<p>{{index .Successes 0}}</p>{{else}}<ul>{{range .Successes}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Errors}}<div class="feedback error">{{if eq 1 (len .Errors)}}<p>{{index .Errors 0}}</p>{{else}}<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Infos}}<div class="feedback info">{{if eq 1 (len .Infos) }}<p>{{index .Infos 0}}</p>{{else}}<ul>{{range .Infos}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="signin_box">

<div id="site_banner">
	<h2>{{.SiteName}}</h2>
</div>

<form method="post" action="/forgot/" id="forgot">
<h3>Request Password Reset Email</h3>

<label for="signin_username">
<input type="email" name="signin_email" id="forgot_email" value='{{.SigninEmail}}' placeholder="Email address"/>
</label>

<p>Enter your email address so that we can send you an email containing a password reset link.</p>

<label for="signin_reset">
	<input type="submit" name="signin_reset" value="Reset Password"/>
</label>

</form>

<script type="text/javascript">
	document.getElementById('forgot_email').focus();
</script>

</div>
{{template "security_footer" .}}
{{end}}
`
