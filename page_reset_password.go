package security

import (
	"html/template"
	"net/http"
	"strings"
)

func ResetPasswordPage(t *template.Template, am AccessManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)

		token := r.URL.Path
		if strings.HasPrefix(token, "/reset.password/") {
			token = token[16:]
		}
		if len(token) > 0 && token[len(token)-1] == '/' {
			token = token[0 : len(token)-1]
		}
		session, err := LookupSession(r, am)
		if err != nil {
			am.Notice(session, `http`, "Error fetching session data %s", err)
			w.Write([]byte("Error fetching session data"))
			return
		}

		type ResetPageData struct {
			SignupPageData

			Token string
		}
		p := &ResetPageData{}
		p.Session = session
		p.Title = []string{"Reset Password"}
		p.Token = token

		baseUrl := am.Setting().GetWithDefault(session.Site(), "base.url", "")
		if baseUrl != "" {
			p.BaseUrl = baseUrl
		}

		// Form has been submitted with new password
		if r.FormValue("new_password1") != "" || r.FormValue("new_password2") != "" {

			failed := false
			if r.FormValue("new_password1") != r.FormValue("new_password2") {
				failed = true
				p.Errors = append(p.Errors, "You entered your desired new password twice, but they did not match. Please try typing your new password in again")
			}
			if len(r.FormValue("new_password1")) < 8 {
				failed = true
				p.Errors = append(p.Errors, "Please choose at least 8 characters for your password.")
			}
			if len(r.FormValue("new_password1")) > 100 {
				failed = true
				p.Errors = append(p.Errors, "Please choose less than 100 characters for your password.")
			}

			if !failed {
				success, message, err := am.ResetPassword(session.Site(), token, r.FormValue("new_password1"), IpFromRequest(r))
				if success {
					p.Successes = append(p.Successes, "Your password has been reset.")

					err = t.ExecuteTemplate(w, "signin_page", p)
					if err != nil {
						am.Notice(session, `http`, "Error displaying 'signup' page: %v", err)
						w.Write([]byte("Error displaying 'signup' page"))
						return
					}
					return
				} else if message != "" {
					p.Errors = append(p.Errors, message)
				} else if err != nil {
					am.Warning(session, `http`, "System error while resetting password: %v", err)
				}
			}
		}

		err = t.ExecuteTemplate(w, "reset_password_page", p)
		if err != nil {
			am.Notice(session, `http`, "Error displaying 'reset_password' page: %v", err)
			w.Write([]byte("Error displaying 'reset_password' page"))
			return
		}

	}
}

var ResetPasswordTemplate = `
{{define "reset_password_page"}}
{{template "security_header" .}}

{{if .Successes}}<div class="feedback success">{{if eq 1 (len .Successes)}}<p>{{index .Successes 0}}</p>{{else}}<ul>{{range .Successes}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Errors}}<div class="feedback error">{{if eq 1 (len .Errors)}}<p>{{index .Errors 0}}</p>{{else}}<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Infos}}<div class="feedback info">{{if eq 1 (len .Infos) }}<p>{{index .Infos 0}}</p>{{else}}<ul>{{range .Infos}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="signin_box">

<div id="site_banner">
	<h2>{{.Session.Theme.Name}}</h2>
</div>

<form method="post" action="/reset.password/{{.Token}}" id="forgot">
<h3>Request Password Account Password</h3>

<label for="new_password1">
<input type="password" name="new_password1" id="new_password1" value='' placeholder="New Password"/>
</label>

<label for="new_password2">
<input type="password" name="new_password2" id="new_password2" value='' placeholder="Re-enter New Password"/>
</label>

<p>We can send you an email that contains a password reset link.</p>

<label for="signin_reset">
	<input type="submit" name="signin_reset" value="Reset Password"/>
</label>

</form>

<script type="text/javascript">
	document.getElementById('new_password1').focus();
</script>

</div>
{{template "security_footer" .}}
{{end}}
`
