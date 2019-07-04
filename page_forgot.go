package security

import (
	"html/template"
	"net/http"
)

func ForgotPage(t *template.Template, am AccessManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)

		session, err := LookupSession(r, am)
		if err != nil {
			am.Notice(session, `http`, "Error fetching session data %s", err)
			w.Write([]byte("Error fetching session data"))
			return
		}

		type Page struct {
			Session     Session
			Title       []string
			SigninEmail string
			Errors      []string
			Infos       []string
			Successes   []string
		}
		p := &Page{}
		p.Title = []string{"Lost Password"}
		p.Session = session

		if r.Method == "POST" && r.FormValue("forgot") != "" {
			p.Infos = append(p.Infos, "If this email address is in our system, you should receive an email shortly with a password reset link.")

			_, err := am.ForgotPasswordRequest(session.Site(), r.FormValue("forgot"), IpFromRequest(r), session.UserAgent(), session.Lang())
			if err != nil {
				ShowError(w, r, t, err, session)
				return
			}
		}

		err = t.ExecuteTemplate(w, "forgot_password_page", p)
		if err != nil {
			am.Notice(session, `html`, "Error displaying 'forgot_password_page': %v", err)
			w.Write([]byte("Error displaying 'forgot' page"))
			return
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
	<h2>{{.Session.Theme.Name}}</h2>
</div>

<form method="post" action="/forgot/" id="forgot">
<h3>Request Password Reset Email</h3>

<label for="forgot_email">
<input type="email" name="forgot" id="forgot_email" value='{{.SigninEmail}}' placeholder="Email address"/>
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
