package security

import (
	"html/template"
	"net/http"
)

func SystemlogPage(t *template.Template, am AccessManager, siteName, siteDescription, supplimentalCss string) func(w http.ResponseWriter, r *http.Request) {
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
		AddSafeHeaders(w)

		type Page struct {
			SiteName        string
			SiteDescription string
			SupplimentalCss string
			Title           []string
			Session         Session
			Entries         []SystemLog
		}

		entries, err := am.GetRecentSystemLog(session)
		if err != nil {
			ShowError(w, r, t, err, siteName)
			return
		}

		p := &Page{siteName, siteDescription, supplimentalCss, []string{"System Log"}, session, entries}

		Render(r, w, t, "system_log", p)
	}
}

var systemlogTemplate = `
{{define "system_log"}}
{{template "admin_header" .}}

<style type="text/css">
</style>

<h1 style="text-align:center; margin-bottom: 1.5em">System Log</h1>

{{if .Entries}}
<table id="system_log">
	<tr>
		<th>Recorded</th>
		<th>IP</th>
		<th>Level</th>
		<th>Component</th>
		<th>Message</th>
	</tr>
	{{range .Entries}}
	<tr>
		<td>{{.GetRecorded}}</td>
		<td>{{.GetIP}}</td>
		<td>{{.GetLevel}}</td>
		<td>{{.GetComponent}}</td>
		<td>{{.GetMessage}}</td>
	</tr>
	{{end}}
</table>
{{else}}
<p style="text-align:center; color: #a55;">No system log entries.</p>
{{end}}
</div>

{{template "admin_footer" .}}
{{end}}
`
