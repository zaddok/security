package security

import (
	"html/template"
	"net/http"
)

func SystemlogPage(t *template.Template, am AccessManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := LookupSession(r, am)
		if err != nil {
			ShowError(w, r, t, err, session)
			return
		}
		if !session.IsAuthenticated() {
			http.Redirect(w, r, "/signup", http.StatusTemporaryRedirect)
			return
		}
		AddSafeHeaders(w)

		type Page struct {
			Session Session
			Title   []string
			Entries []SystemLog
		}

		entries, err := am.GetRecentSystemLog(session)
		if err != nil {
			ShowError(w, r, t, err, session)
			return
		}

		p := &Page{session, []string{"System Log"}, entries}

		Render(r, w, t, "system_log", p)
	}
}

var systemlogTemplate = `
{{define "system_log"}}
{{template "admin_header" .}}

<style type="text/css">
table#system_log tr.error td {
	color: #e22;
}
table#system_log tr.warning td {
	color: #c55;
}
table#system_log tr.notice td {
	color: #e07d10;
}
table#system_log tr.debug td {
	color: #aaa;
}
.togglebar::before{
	content: '\f0b0';
	display: inline-block;
	font-family: FontAwesomeSolid;
	opacity 0.45;
	margin-top: -0.05em;
	font-size: 1.2em;
}
</style>

<h1 style="text-align:center; margin-bottom: 1.5em">System Log</h1>

<script>
var tdi = false
function toggleDebug() {
		if (tdi == false) {
			s = document.getElementsByClassName('debug'); for (var i = 0; i < s.length; i++) { s[i].style.display="table-row"; }
		} else {
			s = document.getElementsByClassName('debug'); for (var i = 0; i < s.length; i++) { s[i].style.display="none" }
		}
		tdi = !tdi
}
</script>

<div class="togglebar" style="text-align:right; font-size: 0.85em; color: #999">
<a onclick="toggleDebug()">Show Debug Messages</a>
</div>

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
	<tr class="{{.GetLevel}} {{.GetComponent}}"{{if eq .GetLevel "debug"}} style="display:none"{{end}}>
		<td style="white-space:nowrap">{{.GetRecorded | audit_time}}</td>
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
