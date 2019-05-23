package security

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

func AccountDetailsPage(t *template.Template, am AccessManager, siteName, siteDescription, supplimentalCss string) func(w http.ResponseWriter, r *http.Request) {
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
		if !session.HasRole("s1") {
			ShowErrorForbidden(w, r, t, siteName)
			return
		}

		AddSafeHeaders(w)

		path := r.URL.Path[1:]
		parts := strings.Split(path, "/")
		uuid := parts[len(parts)-1]

		var person Person = nil

		person, err = am.GetPerson(uuid, session)
		if err != nil {
			ShowError(w, r, t, err, siteName)
			return
		}
		if person == nil {
			ShowErrorNotFound(w, r, t, siteName)
			return
		}

		if r.FormValue("audit") == "history" {

			type Page struct {
				SiteName        string
				SiteDescription string
				Title           []string
				Session         Session
				Person          Person
				Query           string
				EntityAudit     []EntityAuditLogCollection
			}
			changeLog, err := am.GetEntityChangeLog(uuid, session)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}

			p := &Page{
				siteName,
				siteDescription,
				[]string{"Account History", person.DisplayName(), "Accounts"},
				session,
				person,
				r.FormValue("q"),
				changeLog,
			}
			Render(r, w, t, "account_history", p)
			return
		}

		type Page struct {
			SiteName        string
			SiteDescription string
			Title           []string
			Session         Session
			Person          Person
			FirstName       string
			LastName        string
			Email           string
			Query           string
			Feedback        []string
			CustomRoleTypes []RoleType
		}

		p := &Page{
			SiteName:        siteName,
			SiteDescription: siteDescription,
			Title:           []string{person.DisplayName(), "Accounts"},
			Session:         session,
			Person:          person,
			Query:           r.FormValue("q"),
		}

		p.CustomRoleTypes = am.GetCustomRoleTypes()

		if r.Method == "POST" {
			if !session.HasRole("s3") {
				ShowErrorForbidden(w, r, t, siteName)
				return
			}
			csrf := r.FormValue("csrf")
			if csrf != session.GetCSRF() {
				am.Log().Warning("Potential CSRF attack detected. '" + IpFromRequest(r) + "', '" + r.URL.String() + "'")
				ShowErrorForbidden(w, r, t, siteName)
				return
			}
			feedback, err := updateAccountWithFormValues(am, person, session, r)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
			if len(feedback) == 0 {
				http.Redirect(w, r, "/z/accounts?q="+url.QueryEscape(r.FormValue("q")), http.StatusTemporaryRedirect)
				return
			}
			p.Feedback = feedback
			p.FirstName = r.FormValue("first_name")
			p.LastName = r.FormValue("last_name")
			p.Email = r.FormValue("email")

		}

		Render(r, w, t, "account_details", p)
	}
}

// If /account.details/ detects some posted data, we can do a account update.
func updateAccountWithFormValues(am AccessManager, person Person, session Session, r *http.Request) ([]string, error) {
	var warnings []string

	if r.FormValue("first_name") == "" &&
		r.FormValue("last_name") == "" &&
		r.FormValue("password") == "" &&
		r.FormValue("email") == "" {
		return warnings, nil
	}
	firstName := r.FormValue("first_name")
	lastName := r.FormValue("last_name")
	email := r.FormValue("email")
	password := r.FormValue("password")
	roles := ""

	if firstName == "" {
		warnings = append(warnings, "Please specify a first name.")
	}
	if lastName == "" {
		warnings = append(warnings, "Please specify a last name.")
	}
	if email == "" {
		warnings = append(warnings, "Please specify an email address.")
	} else {
		ev := CheckEmail(email)
		if ev != "" {
			warnings = append(warnings, "Please specify a valid email adddress. "+ev+".")
		}
	}

	for i := 1; i < 6; i++ {
		uid := fmt.Sprintf("s%d", i)
		if r.FormValue(uid) != "" {
			roles = roles + uid + ":"
		}
	}
	for _, i := range am.GetCustomRoleTypes() {
		if r.FormValue(i.GetUid()) != "" {
			roles = roles + i.GetUid() + ":"
		}
	}
	if roles != "" {
		roles = roles[0 : len(roles)-1]
	}

	if len(warnings) == 0 {
		return warnings, am.UpdatePerson(person.GetUuid(), firstName, lastName, email, roles, password, session)
	} else {
		return warnings, nil
	}
}

var accountDetailsTemplate = `
{{define "account_details"}}
{{template "admin_header" .}}
<div id="actions">
<a href="/z/account.details/{{.Person.Uuid}}?q={{.Query}}&audit=history" class="history">History</a>
{{if not .Person.LastSignin}}
<a href="/z/accounts?q={{.Query}}&delete={{.Person.Uuid}}&csrf={{.Session.GetCSRF}}" class="delete">Delete</a>
{{end}}
</div>

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
<div style="margin-top: -1.7rem"><a class="back" href="/z/accounts?q={{.Query}}">Back</a></div>

<div id="editform">
<h1>{{.Person.FirstName}} {{.Person.LastName}}</h1>

{{if .Feedback}}<div class="feedback error">{{if eq 1 (len .Feedback)}}<p>{{index .Feedback 0}}</p>{{else}}<ul>{{range .Feedback}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<form method="post">
<input type="hidden" name="q" value="{{.Query}}"/>
<input type="hidden" name="csrf" value="{{.Session.GetCSRF}}"/>
<table id="account_view" class="form">
	<tr>
		<th>First Name</th>
		<td><input type="text" name="first_name" value="{{.Person.FirstName}}".></td>
	</tr>
	<tr>
		<th>Last Name</th>
		<td><input type="text" name="last_name" value="{{.Person.LastName}}"/></td>
	</tr>
	<tr>
		<th>Email</th>
		<td><input type="email" name="email" value="{{.Person.Email}}" style="width: 18em"></td>
	</tr>

	<tr><td>&nbsp;</td><td></td></tr>
	<tr>
		<th>Password</th>
		<td><input type="password" name="password" value="" style="width: 18em"/><br>
		Enter a new pasword if you wish to change<br>
		this users password. Leave the pasword blank<br>
		if you do not wish to change this users password.</td>
	</tr>

	<tr><td>&nbsp;</td><td></td></tr>

	<tr>
		<th>Administrator</th>
		<td><input type="checkbox" name="s1" value="s1"{{if .Person.HasRole "s1"}} checked="checked"{{end}}> View administrative area</td>
	</tr>
	<tr>
		<th>System Settings</th>
		<td><input type="checkbox" name="s2" value="s2"{{if .Person.HasRole "s2"}} checked="checked"{{end}}> Manage System settings</td>
	</tr>
	<tr>
		<th>Accounts</th>
		<td><input type="checkbox" name="s3" value="s3"{{if .Person.HasRole "s3"}} checked="checked"{{end}}> Manage Accounts</td>
	</tr>
	<tr>
		<th>Picklists</th>
		<td><input type="checkbox" name="s4" value="s4"{{if .Person.HasRole "s4"}} checked="checked"{{end}}> Manage Picklists</td>
	</tr>

	<tr><td>&nbsp;</td><td></td></tr>

{{range .CustomRoleTypes}}
	<tr>
		<th>{{.Name}}</th>
		<td><input type="checkbox" name="{{.Uid}}" value="{{.Uid}}"{{if $.Person.HasRole .Uid}} checked="checked"{{end}}/> {{.Description}}</td>
	</tr>
{{end}}

	<tr><td>&nbsp;</td><td></td></tr>

	<tr><td></td><td><input type="submit" value="Save"></td></tr>
</table>
</form>

</div>
{{template "admin_footer" .}}
{{end}}
`
var accountHistoryTemplate = `
{{define "account_history"}}
{{template "admin_header" .}}
<div style="margin-top: -0.9rem"><a class="back" href="/z/account.details/{{.Person.Uuid}}?q={{.Query}}">Back</a></div>

<h1>Change History for {{.Person.FirstName}} {{.Person.LastName}}</h1>

{{template "show_history" .}}

{{template "admin_footer" .}}
{{end}}


{{define "show_history"}}
<style type="text/css">
h1 {
	text-align:center;
}
#tableonly table {
	margin-top: 0.5em;
	margin-bottom: 0em;
	margin-left: auto;
	margin-right: auto;
}
.audit_set {
	background: rgba(204, 204, 238, 0.35) !important;
	margin-left: auto;
	margin-right: auto;
	border-radius: 0.5em;
	min-width: 20em;
	padding: 0.8em;
	padding-right: 0em;
	max-width: 40em;
	margin-top: 1em;
}
.audit_set td span.add::before { font-family: FontAwesomeSolid; content:"\f055"; }
.audit_set td span.update::before { font-family: FontAwesomeSolid; content:"\f35a"; }
.audit_set td span.delete::before { font-family: FontAwesomeSolid; content:"\f056"; }
</style>

<div id="tableonly">

{{range .EntityAudit}}
<div class="audit_set">
<table style="width:100%;margin-top:-0.4em;margin-left:-0.4em;color:#77c;"><tr><td>{{.GetDate}}</td><td style="text-align:right">{{.GetPersonName}}</td></tr></table>
<table>
{{range .GetItems}}
<tr>
<td style="text-align:left; font-weight: bold;white-space:nowrap">{{.GetAttribute}}</td>
{{if .IsPicklistType}}

{{if eq .GetActionType "delete"}}
	<td style="text-align:right;white-space:nowrap;"></td>
	{{else}}{{$l := lookup $.Session.Site .ValueType .OldValue}}
	<td style="text-align:right;white-space:nowrap;">{{if eq $l ""}}{{.OldValue}}{{else}}{{$l}}{{end}}</td>
{{end}}
	<td style="width:1%"><span class="{{.GetActionType}}"></span></td>
{{if eq .GetActionType "delete"}}
	<td style="text-align:left; width: 99%">{{lookup $.Session.Site .ValueType .OldValue}}</td>
{{else}}
	<td style="text-align:left; width: 99%">{{lookup $.Session.Site .ValueType .NewValue}}</td>
{{end}}
{{else}}

{{if eq .GetValueType ""}}
	<td style="text-align:right;white-space:nowrap"></td>
	<td style="width:1%"><span class="{{.GetActionType}}"><a href="{{.NewValue}}">{{.OldValue}}</a></span></td>
{{else}}

{{if eq .GetActionType "delete"}}
	<td style="text-align:right;white-space:nowrap"></td>
{{else}}
	<td style="text-align:right;white-space:nowrap">{{.OldValue}}</td>
{{end}}
	<td style="width:1%"><span class="{{.GetActionType}}"></span></td>
{{if eq .GetActionType "delete"}}
	<td style="text-align:left; width: 99%">{{.OldValue}}</td>
{{else}}
	<td style="text-align:left; width: 99%">{{.NewValue}}</td>
{{end}}
{{end}}
{{end}}
</tr>
{{end}}
</table>
</div>
{{end}}

</div>
{{end}}

`
