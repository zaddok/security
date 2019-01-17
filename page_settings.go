package main

import (
	"html/template"
	"net/http"
	"sort"
	"strings"

	"git.tai.io/zadok/security"
)

func SettingsPage(t *template.Template, am security.AccessManager, siteName, siteDescription, supplimentalCss string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := security.LookupSession(r, am)
		if err != nil {
			security.ShowError(w, r, t, err, SITE)
			return
		}
		if !session.IsAuthenticated() {
			http.Redirect(w, r, "/signup", http.StatusTemporaryRedirect)
			return
		}
		security.AddSafeHeaders(w)

		key := strings.TrimSpace(r.FormValue("key"))
		value := strings.TrimSpace(r.FormValue("value"))
		if key != "" {
			err := am.Setting().Put(session.GetSite(), key, value)
			if err != nil {
				security.ShowError(w, r, t, err, SITE)
				return
			}
		}

		delete := strings.TrimSpace(r.FormValue("delete"))
		if delete != "" {
			err := am.Setting().Put(session.GetSite(), delete, "")
			if err != nil {
				security.ShowError(w, r, t, err, SITE)
				return
			}
		}

		edit := strings.TrimSpace(r.FormValue("edit"))
		if edit != "" {

			type Page struct {
				SiteName        string
				SiteDescription string
				SupplimentalCss string
				Title           []string
				Session         security.Session
				Key             string
				Value           string
			}
			value := am.Setting().GetWithDefault(session.GetSite(), edit, "")
			if err != nil {
				security.ShowError(w, r, t, err, SITE)
				return
			}
			security.Render(r, w, t, "setting_edit", &Page{siteName, siteDescription, supplimentalCss, []string{"Edit setting", "System Settings"}, session, edit, value})

			return
		}

		type Page struct {
			SiteName        string
			SiteDescription string
			SupplimentalCss string
			Title           []string
			Session         security.Session
			Settings        [][]string
		}

		err = r.ParseForm()
		if err != nil {
			security.ShowError(w, r, t, err, SITE)
			return
		}

		var values [][]string

		items := am.Setting().List(session.GetSite())
		for k, v := range items {
			values = append(values, []string{k, v})
		}

		sort.Slice(values, func(i, j int) bool {
			return values[j][0] > values[i][0]
		})

		security.Render(r, w, t, "settings", &Page{siteName, siteDescription, supplimentalCss, []string{"System Settings"}, session, values})
	}
}

var settingsTemplate = `
{{define "settings"}}
{{template "admin_header" .}}
<div id="actions">
<a href="javascript:document.getElementById('myModal').style.display='block'" class="note">Add Setting</a>
</div>

<style type="text/css">
/* Popup box css */
.modal { display: none; position: fixed; z-index: 1; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgb(0,0,0); background-color: rgba(0,0,0,0.4); }
.modal .close { color: #8d8; float: right; font-size: 1.7em; font-weight: bold; }
.modal .close:hover, .modal .close:focus { color: #484; text-decoration: none; cursor: pointer; }
.modal-header { padding: 2px 16px; background-color: #5cb85c; color: white; }
.modal-header h2 { margin: 0 1.5em 0 0; padding: 0.3em 0 0.3em 0; font-size: 1.2em; color: #347534; opacity: 0.8; }
.modal-header h2::before { font-family: FontAwesomeSolid; padding-right: 0.5em; content: "\f46c"; opacity: 0.6; }
.modal-body { padding: 1em 3em; }
.modal-footer { padding: 0.3em 3em; background-color: #5cb85c; color: white; text-align: right; }
.modal-content {
  margin: 15% auto; /* 15% from the top and centered */
  padding: 20px;
  border: 1px solid #888;
  position: relative;
  background-color: #fefefe;
  padding: 0;
  width: 80%;
  min-width: 22em;
  box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2),0 6px 20px 0 rgba(0,0,0,0.19);
  animation-name: animatetop;
  animation-duration: 0.2s
}
@keyframes animatetop { from {top: -300px; opacity: 0} to {top: 0; opacity: 1} }

table tr:hover a.delete::before {
	opacity: 0.5;
}
table tr:hover a.delete:hover::before {
	opacity: 0.5;
	color: red;
}
a.delete::before {
	font-family: FontAwesome;
	content: "\f2ed";
	opacity: 0.1;
}
</style>

{{if .Settings}}{{else}}
<br><br><br>
{{end}}
<h1 style="text-align:center; margin-bottom: 1.5em">System Settings</h1>

{{if .Settings}}
<table id="student_search_results">
	<tr>
		<th>Name</th>
		<th>Value</th>
	</tr>
	{{range .Settings}}{{$k := index . 0}}{{$v := index . 1}}{{if ne $k "smtp.password"}}{{if ne $v ""}}
	<tr>
		<td><a href="/z/settings?edit={{$k}}">{{$k}}</a></td>
		<td><a href="/z/settings?edit={{$k}}">{{$v}}</a></td>
		<td><a href="/z/settings?delete={{$k}}" class="delete"></a></td>
		<td><a href="/z/settings?edit={{$k}}" class="edit"></a></td>
	</tr>
{{end}}{{end}}{{end}}
</table>
{{else}}
<p style="text-align:center; color: #a55;">No settings found.</p>
{{end}}
</div>


<div id="myModal" class="modal">
<div class="modal-content">
  <div class="modal-header">
    <span class="close">&times;</span>
    <h2>Add System Setting</h2>
  </div>
  <form method="post">
	<div class="modal-body">
	<table>
	<tr><th>Key</th><td><input type="text" name="key" placeholder="setting.key"/></td></tr>
	<tr><th>Value</th><td><input type="text" name="value" placeholder="value"/></td></tr>
	</table>
	</div>
  <div class="modal-footer">
    <input type="Submit" name="Add" value="Add Setting" />
  </div>
</div>
</div>
<script type="text/javascript">
var modal = document.getElementById('myModal');
var span = document.getElementsByClassName("close")[0];
span.onclick = function() { modal.style.display = "none"; }
window.onclick = function(event) { if (event.target == modal) { modal.style.display = "none"; } }
</script>

{{template "admin_footer" .}}
{{end}}

`

var settingEditTemplate = `
{{define "setting_edit"}}
{{template "admin_header" .}}
<div style="margin-top: -1.7rem"><a class="back" href="/z/settings">Back</a></div>

<style type="text/css">
#editform table {
        margin-left:auto;
        margin-right:auto;
}
#editform h1 {
        text-align:center;
}
#editform input {
        font-size: 1rem;
}
#editform table th {
        vertical-align:top;
}

</style>

<div id="editform">
<h1>Edit Setting</h1>

<form method="post">
<table id="setting_edit" class="form"><input type="hidden" name="key" value="{{.Key}}"/>
        <tr>
                <th>Key</th>
                <td>{{.Key}}</td>
        </tr>
        <tr>
                <th>Value</th>
                <td><input type="text" name="value" value="{{.Value}}"/></td>
        </tr>

        <tr><td>&nbsp;</td><td></td></tr>

        <tr><td></td><td><input type="submit" value="Save"></td></tr>
</table>
</form>

{{template "admin_footer" .}}
{{end}}
`
