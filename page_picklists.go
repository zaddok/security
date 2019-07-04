package security

import (
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func PicklistPage(t *template.Template, am AccessManager) func(w http.ResponseWriter, r *http.Request) {
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

		path := r.URL.Path[1:]
		parts := strings.Split(path, "/")
		picklistName := parts[len(parts)-1]
		if picklistName == "picklist" {
			picklistName = ""
		}

		key := strings.TrimSpace(r.FormValue("key"))
		value := strings.TrimSpace(r.FormValue("value"))
		description := strings.TrimSpace(r.FormValue("description"))
		index, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("index")), 10, 64)
		if r.Method == "POST" && key != "" && picklistName != "" {
			if !session.HasRole("s4") {
				ShowErrorForbidden(w, r, t, session)
				return
			}
			err := am.PicklistStore().AddPicklistItem(session.Site(), picklistName, key, value, description, index)
			if err != nil {
				ShowError(w, r, t, err, session)
				return
			}
		}

		toggle := strings.TrimSpace(r.FormValue("toggle"))
		if toggle != "" && picklistName != "" {
			if !session.HasRole("s4") {
				ShowErrorForbidden(w, r, t, session)
				return
			}
			err := am.PicklistStore().TogglePicklistItem(session.Site(), picklistName, toggle)
			if err != nil {
				ShowError(w, r, t, err, session)
				return
			}
		}

		edit := strings.TrimSpace(r.FormValue("edit"))
		if edit != "" {

			type Page struct {
				Session Session
				Title   []string
				Key     string
				Value   string
			}
			value := am.Setting().GetWithDefault(session.Site(), edit, "")
			if err != nil {
				ShowError(w, r, t, err, session)
				return
			}
			Render(r, w, t, "picklist_edit", &Page{session, []string{"Edit Picklist Item", "Picklists", "Administration"}, edit, value})

			return
		}

		type Page struct {
			Session       Session
			Title         []string
			Picklists     []string
			Picklist      string
			PicklistItems []PicklistItem
		}
		p := &Page{
			Session: session,
		}

		err = r.ParseForm()
		if err != nil {
			ShowError(w, r, t, err, session)
			return
		}

		all, err := am.PicklistStore().GetPicklists(session.Site())
		if err != nil {
			ShowError(w, r, t, err, session)
			return
		}
		for k, _ := range all {
			p.Picklists = append(p.Picklists, k)
		}
		sort.Slice(p.Picklists, func(i, j int) bool {
			return p.Picklists[j] > p.Picklists[i]
		})

		if picklistName == "" && len(p.Picklists) > 0 {
			picklistName = p.Picklists[0]
		}

		p.Picklist = picklistName
		p.Title = []string{"Picklists", picklistName}

		p.PicklistItems, err = am.PicklistStore().GetPicklistOrdered(session.Site(), picklistName)
		if err != nil {
			ShowError(w, r, t, err, session)
			return
		}

		Render(r, w, t, "picklist_admin", p)
	}
}

var picklistTemplate = `
{{define "picklist_admin"}}
{{template "admin_header" .}}
<div id="actions">
{{if $.Session.HasRole "s4"}}<a href="javascript:document.getElementById('myModal').style.display='block'" class="note">Add Item</a>{{end}}
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

div.picklist_menu {
	float: left;
	width: 17em;
}
div.picklist_menu ul li {
	list-style: none;
	padding-bottom: 0.3em;
}
div.picklist_menu ul {
	padding-left: 0;
}
body {
	background: url(/grey.png);
	background-size: 17em auto;
	background-repeat: repeat-y;
}

tr td a.deprecated::before:hover,
tr td a.not_deprecated::before:hover {
	text-decoration: none;
}
tr td a.deprecated::before,
tr td a.not_deprecated::before {
	display: inline-block;
	color: #888;
	padding-right: 0.2em;
	padding-left: 0.2em;
	font-size: 0.9em;
	font-family: FontAwesomeSolid;
}
tr td a.deprecated::before {
	content: "\f070";
}
tr td a.not_deprecated::before {
	content: "\f06e";
}

.picklist_items h2 {
	text-align: center;
}
.picklist_items h2::before {
	padding-right: 0.3em;
	padding-left: 0.2em;
	font-size: 0.9em;
	opacity: 0.3;
	font-family: FontAwesomeSolid;
	content: "\f022";

}
table tbody tr td:nth-child(4) { text-align: center; }
table { margin-left: auto; margin-right: auto; }
</style>


<div class="picklist_menu">
<ul>
{{range .Picklists}}
<li><a href="/z/picklist/{{.}}">{{.}}</a></li>
{{end}}
</ul>
</div>

<div class="picklist_items">
<h2>{{.Picklist}}</h2>
<table id="picklist_item_table">
<thead>
<tr>
	<th>Key</th>
	<th>Value</th>
	<th>Description</th>
	<th>Deprecated</th>
	<th data-sort-method="number">Index</th>
</tr>
</thead>
<tbody>
{{range .PicklistItems}}
<tr{{if .IsDeprecated}}class="deprecated"{{end}}>
	<td>{{.Key}}</td>
	<td>{{.Value}}</td>
	<td>{{.Description}}</td>
	<td><a class="{{if .IsDeprecated}}deprecated{{else}}not_deprecated{{end}}"{{if $.Session.HasRole "s4"}} href="/z/picklist/{{.Picklist}}?toggle={{.Key}}"{{end}}></a></td>
	<td>{{.Index}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>

<script src='/tablesort.js'></script>
<script src='/tablesort.number.js'></script>
<script>new Tablesort(document.getElementById('picklist_item_table'));</script>


<div id="myModal" class="modal">
<div class="modal-content">
  <div class="modal-header">
    <span class="close">&times;</span>
    <h2>Add Picklist Item</h2>
  </div>
  <form method="post">
	<div class="modal-body">
	<table>
		<tr><th>Key</th><td><input type="text" name="key" placeholder="key"/></td></tr>
		<tr><th>Value</th><td><input type="text" name="value" placeholder="value"/></td></tr>
		<tr><th>Description</th><td><textarea name="description" class="description"></textarea></td></tr>
		<tr><th>Index</th><td><input type="text" name="index" placeholder="10"/></td></tr>
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
</script>

{{template "admin_footer" .}}
{{end}}

`
