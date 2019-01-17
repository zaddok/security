package security

import (
	"html/template"
	"net/http"
	"sort"
	"strings"
)

func PicklistPage(t *template.Template, am AccessManager, siteName, siteDescription, supplimentalCss string) func(w http.ResponseWriter, r *http.Request) {
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

		key := strings.TrimSpace(r.FormValue("key"))
		value := strings.TrimSpace(r.FormValue("value"))
		if key != "" {
			err := am.Setting().Put(session.GetSite(), key, value)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
		}

		delete := strings.TrimSpace(r.FormValue("delete"))
		if delete != "" {
			err := am.Setting().Put(session.GetSite(), delete, "")
			if err != nil {
				ShowError(w, r, t, err, siteName)
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
				Session         Session
				Key             string
				Value           string
			}
			value := am.Setting().GetWithDefault(session.GetSite(), edit, "")
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
			Render(r, w, t, "setting_edit", &Page{siteName, siteDescription, supplimentalCss, []string{"Edit setting", "System Settings"}, session, edit, value})

			return
		}

		type Page struct {
			SiteName        string
			SiteDescription string
			SupplimentalCss string
			Title           []string
			Session         Session
			Picklist        []string
			PicklistItems   []PicklistItem
		}
		p := &Page{
			SiteName:        siteName,
			SiteDescription: siteDescription,
			SupplimentalCss: supplimentalCss,
			Title:           []string{"Picklists"},
			Session:         session,
		}

		err = r.ParseForm()
		if err != nil {
			ShowError(w, r, t, err, siteName)
			return
		}

		all, err := am.PicklistStore().GetPicklists(session.GetSite())
		if err != nil {
			ShowError(w, r, t, err, siteName)
			return
		}
		for k, _ := range all {
			p.Picklist = append(p.Picklist, k)
		}
		sort.Slice(p.Picklist, func(i, j int) bool {
			return p.Picklist[j] > p.Picklist[i]
		})
		p.PicklistItems, err = am.PicklistStore().GetPicklistOrdered(session.GetSite(), p.Picklist[0])
		if err != nil {
			ShowError(w, r, t, err, siteName)
			return
		}

		Render(r, w, t, "picklist_admin", p)
	}
}

var picklistTemplate = `
{{define "picklist_admin"}}
{{template "admin_header" .}}
<div id="actions">
<a href="javascript:document.getElementById('myModal').style.display='block'" class="note">Add Item</a>
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


<div class="picklist_menu">
<ul>
{{range .Picklist}}
<li><a href="/z/picklist/{{.}}">{{.}}</a></li>
{{end}}
</ul>
</div>

<div class="picklist_items">
<ul>
{{range .PicklistItems}}
<li>{{.}}</li>
{{end}}
</ul>
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
    <input type="Submit" name="Add" value="Add Picklist Item" />
  </div>
</div>
</div>
<script type="text/javascript">
var modal = document.getElementById('myModal');
var span = document.getElementsByClassName("close")[0];
span.onclick = function() { modal.style.display = "none"; }
window.onclick = function(event) { if (event.target == modal) { modal.style.display = "none"; } }
</script>,

{{template "admin_footer" .}}
{{end}}

`
