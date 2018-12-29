package security

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

func ActivatePage(t *template.Template, am AccessManager, siteName, siteDescription string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		p := &SignupPageData{}
		p.SiteName = siteName
		p.SiteDescription = siteDescription

		token := r.URL.Path
		if strings.HasPrefix(token, "/activate/") {
			token = token[10:]
		}
		if len(token) > 0 && token[len(token)-1] == '/' {
			token = token[0 : len(token)-1]
		}

		ip := IpFromRequest(r)
		cookie, failure, err := am.ActivateSignup(HostFromRequest(r), token, ip)

		if len(cookie) > 0 {
			/*
				// Uncomment if you wish clicking on the activate link to auto-sign in the person
				// clicking on the activation link. For security reasons, its better to require
				// the activation link and the users password.
				c := &http.Cookie{
					Name:     "z",
					Value:    cookie,
					Path:     "/",
					Secure:   false,
					HttpOnly: true,
					Expires:  time.Now().Add(time.Duration(COOKIE_DAYS) * 24 * time.Hour),
					MaxAge:   60 * 60 * 24 * COOKIE_DAYS,
				}
				http.SetCookie(w, c)
			*/
			p.Successes = append(p.Successes, "Thank you for confirming your email address. Your account is now active.")
		}
		if failure != "" {
			p.Errors = append(p.Errors, failure)
		}
		if err != nil {
			p.Errors = append(p.Errors, fmt.Sprintf("Activation problem: %s", err))
		}
		p.AllowSignup = !(strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no")) == "no")

		err = t.ExecuteTemplate(w, "signin_page", p)
		if err != nil {
			am.Log().Notice("Error displaying 'signup' page: %v", err)
			w.Write([]byte("Error displaying 'signup' page"))
			return
		}
	}
}

var ActivateTemplate = `
{{define "activate_account_page"}}
{{template "security_header" .}}

{{if .Successes}}<div class="success">{{if eq 1 (len .Successes)}}<p>{{index .Successes 0}}</p>{{else}}<ul>{{range .Successes}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Errors}}<div class="error">{{if eq 1 (len .Errors)}}<p>{{index .Errors 0}}</p>{{else}}<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Infos}}<div class="info">{{if eq 1 (len .Infos) }}<p>{{index .Infos 0}}</p>{{else}}<ul>{{range .Infos}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="signin_box">

<div id="site_banner">
	<h2>{{.SiteName}}</h2>
</div>

<form method="post" action="/signin" id="signin">
<h3>Sign in</h3>

<label for="signin_username">
<input type="text" name="signin_email" id="signin_email" value='{{.SigninEmail}}' placeholder="Email address"/>
</label>

<label for="signin_password">
<input type="password" name="signin_password" id="signin_password" value="{{.Password}}" placeholder="Password"/></span>
	<input type="submit" name="signin" value="Sign in"/>
</label>


<p><a href="/forgot/">Forgot your password?</a></p>

</form>


</div>
{{template "security_footer" .}}
{{end}}
`
