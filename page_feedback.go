package security

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

func FeedbackPage(t *template.Template, am AccessManager, siteName, siteDescription, supplimentalCss string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := LookupSession(r, am)
		if err != nil {
			ShowError(w, r, t, err, siteName)
			return
		}
		if !session.IsAuthenticated() {
			http.Redirect(w, r, "/signup", http.StatusTemporaryRedirect)
			return
		}
		if !session.HasRole("c3") {
			ShowErrorForbidden(w, r, t, siteName)
			return
		}
		AddSafeHeaders(w)

		type Page struct {
			SiteName         string
			SiteDescription  string
			SupplimentalCss  string
			Title            []string
			Session          Session
			MessageSubject   string
			MessageText      string
			CurrentUserAgent string
			CurrentIP        string
			CurrentUrl       string
			Feedback         []string
			BackLink         string
		}

		p := &Page{
			SiteName:         siteName,
			SiteDescription:  siteDescription,
			SupplimentalCss:  supplimentalCss,
			Title:            []string{"Send feedback", "Feedback"},
			Session:          session,
			CurrentUrl:       r.Referer(),
			CurrentUserAgent: r.UserAgent(),
			CurrentIP:        IpFromRequest(r),
		}

		if r.FormValue("message_subject") != "" {
			p.MessageSubject = r.FormValue("message_subject")
		}
		if r.FormValue("message_text") != "" {
			p.MessageText = r.FormValue("message_text")
		}
		if r.FormValue("current_url") != "" {
			p.CurrentUrl = r.FormValue("current_url")
		}

		// Check current url for security reasons
		cu, err := url.Parse(p.CurrentUrl)
		if err != nil {
			p.CurrentUrl = ""
			fmt.Println("couldnt parse currrent url")
		} else {
			if cu.Host != "" {
				p.CurrentUrl = p.CurrentUrl[strings.Index(p.CurrentUrl, cu.Host)+len(cu.Host):]
				//fmt.Printf("currrent url host mismatch '%s' != '%s'\n", cu.Host, r.URL.Host)
				//p.CurrentUrl = ""
			}
		}

		if r.Method == "POST" {
			if p.CurrentUrl == "" {
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			} else {
				http.Redirect(w, r, p.CurrentUrl, http.StatusTemporaryRedirect)
			}

		}

		// Not saved, show creation form, with feedback if needed
		Render(r, w, t, "feedback_send", p)

		return
	}
}

var feedbackTemplate = `
{{define "feedback_send"}}
{{template "security_header" .}}

<style type="text/css">
}
#editform input[type=text] {
	font-size: 1rem;
	width: 20em;
}
#editform textarea {
	font-size: 1rem;
	width: 20em;
	margin-bottom: 1.7em;
	height: 8em;
}
#editform table th {
	vertical-align:top;
}
#editform b {
	margin-top: 0.7em;
	font-size: 0.9em;
}
#editform b {
	font-family: "Helvetica Neue", Helvetica, sans-serif;
	color: white;
	display: block;
	font-weight: normal;
	padding-top: 0.5em
}

</style>

{{if .BackLink}}
<div style="margin-top: -1.1rem"><a class="back" href="{{.BackLink}}">Back</a></div>
{{end}}

<div id="signin_box">

<div id="site_banner">
	<h2>Send Feedback</h2>
</div>

<div id="editform">

<p>Please take a moment to submit your feedback, comments, or suggestions.</p>

<form method="post" action="/z/feedback">
<input type="hidden" name="csrf" value="{{.Session.GetCSRF}}"/>
<input type="hidden" name="current_url" value="{{.CurrentUrl}}"/>

<b>Subject</b>
<input type="text" name="message_subject" placeholder="Subject of your feedback or suggestion" value="{{.MessageSubject}}"/>
<b>Details</b>
<textarea name="message_text">{{.MessageText}}</textarea>


<input type="submit" value="Send Feedback">
</table>
</form>

</div>
</div>
</div>
{{template "security_footer" .}}
{{end}}
`
