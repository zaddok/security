package security

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
)

func AccountsPage(t *template.Template, am AccessManager) func(w http.ResponseWriter, r *http.Request) {
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
		if !session.HasRole("s1") {
			ShowErrorForbidden(w, r, t, session)
			return
		}

		AddSafeHeaders(w)

		if r.FormValue("new") == "create" {
			if !session.HasRole("s3") {
				ShowErrorForbidden(w, r, t, session)
				return
			}

			type Page struct {
				Session         Session
				Title           []string
				Query           string
				FirstName       string
				LastName        string
				Email           string
				Feedback        []string
				CustomRoleTypes []RoleType
			}

			p := &Page{
				Session:         session,
				Title:           []string{"Create new account", "Accounts"},
				Query:           r.FormValue("q"),
				CustomRoleTypes: am.GetCustomRoleTypes(),
			}

			p.FirstName = r.FormValue("first_name")
			p.LastName = r.FormValue("last_name")
			p.Email = r.FormValue("email")

			if r.Method == "POST" {
				csrf := r.FormValue("csrf")
				if csrf != session.CSRF() {
					am.Warning(session, `security`, "Potential CSRF attack detected. "+r.URL.String())
					ShowErrorForbidden(w, r, t, session)
					return
				}

				feedback, err := createAccountWithFormValues(am, session, r)
				if err != nil {
					ShowError(w, r, t, err, session)
					return
				}
				if len(feedback) == 0 {
					// Saved with no errors
					http.Redirect(w, r, "/z/accounts?q="+url.QueryEscape(r.FormValue("q")), http.StatusTemporaryRedirect)
					return
				}
				p.Feedback = feedback
			}

			Render(r, w, t, "account_create", p)
			return
		}

		type Page struct {
			Session         Session
			Title           []string
			Query           string
			Accounts        []Person
			CustomRoleTypes []RoleType
			Feedback        []string
		}
		var feedback []string

		if r.FormValue("delete") != "" {
			if !session.HasRole("s3") || r.FormValue("csrf") != session.CSRF() {
				ShowErrorForbidden(w, r, t, session)
				return
			}
			uuid := r.FormValue("delete")
			err := am.DeletePerson(uuid, session)
			if err != nil {
				ShowError(w, r, t, err, session)
				return
			}
			feedback = append(feedback, "User account has been deleted.")
		}

		err = r.ParseForm()
		if err != nil {
			ShowError(w, r, t, err, session)
			return
		}
		q := r.Form.Get("q")

		var accounts []Person = nil
		if q != "" {
			accounts, err = am.SearchPeople(q, session)
			if err != nil {
				ShowError(w, r, t, err, session)
				return
			}
		}
		cut := -1
		for x, a := range accounts {
			if a.Uuid() == r.FormValue("delete") {
				cut = x
				break
			}
		}
		if cut >= 0 {
			if len(accounts) == 1 {
				accounts = []Person{}
			} else {
				accounts = append(accounts[0:cut], accounts[cut+1:]...)
			}
		}

		sort.Slice(accounts, func(i, j int) bool {
			return accounts[j].FirstName() > accounts[i].FirstName()
		})
		p := &Page{
			session,
			[]string{"Accounts"},
			q,
			accounts,
			am.GetCustomRoleTypes(),
			feedback,
		}

		Render(r, w, t, "accounts", p)
	}
}

// If /account.details/ detects some posted data, we can do a account update.
func createAccountWithFormValues(am AccessManager, session Session, r *http.Request) ([]string, error) {
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
			warnings = append(warnings, "Please specify a valid email adddress. "+ev)
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
		var pw *string = nil
		if password != "" {
			pw = HashPassword(password)
		}
		_, err := am.AddPerson(session.Site(), firstName, lastName, email, roles, pw, IpFromRequest(r), session)
		return warnings, err
	} else {
		return warnings, nil
	}
}

var accountsTemplate = `
{{define "accounts"}}
{{template "admin_header" .}}
{{if .Query}}
<div id="actions">
{{if $.Session.HasRole "s3"}}
<a href="/z/accounts?q={{.Query}}&new=create" class="new_person">New Account</a>
{{end}}
</div>
{{end}}

{{if .Feedback}}<div class="feedback success">{{if eq 1 (len .Feedback) }}<p>{{index .Feedback 0}}</p>{{else}}<ul>{{range .Feedback}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div class="search_layout">
{{if .Accounts}}{{else}}
<br><br><br>
{{end}}
<h1>Accounts</h1>
<div class="search">
<form method="get" action="/z/accounts">
<div id="q"><input type="search" name="q" id="qi" value="{{.Query}}" placeholder="First name, Last name, or Student number"/></div>
</form>
</div>

{{if .Accounts}}
<table id="student_search_results">
	<tr>
		<th>Name</th>
		<th>Email</th>
		<th>Last Access</th>
	</tr>
{{range .Accounts}}{{if .Email}}
	<tr>
		<td><a href="/z/account.details/{{.Uuid}}?q={{$.Query}}">{{.FirstName}} {{.LastName}}</a></td>
		<td><a href="/z/account.details/{{.Uuid}}?q={{$.Query}}">{{.Email}}</a></td>
		<td><a href="/z/account.details/{{.Uuid}}?q={{$.Query}}">{{.LastSignin | log_date}}</a></td>
	</tr>
{{end}}{{end}}
</table>
{{else}}{{if .Query}}
<p style="text-align:center; color: #a55;">No search results found for &ldquo;{{.Query}}&rdquo;.</p>
{{end}}{{end}}
</div>

<script type="text/javascript">
	document.getElementById('qi').focus();
</script>
{{template "admin_footer" .}}
{{end}}
`

var accountCreateTemplate = `
{{define "account_create"}}
{{template "admin_header" .}}

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
<div style="margin-top: -0.7rem"><a class="back" href="/z/accounts?q={{.Query}}">Back</a></div>

{{if .Feedback}}<div class="feedback error">{{if eq 1 (len .Feedback)}}<p>{{index .Feedback 0}}</p>{{else}}<ul>{{range .Feedback}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="editform">
<h1>New Account</h1>

<form method="post"><input type="hidden" name="q" value="{{.Query}}"/><input type="hidden" name="csrf" value="{{.Session.CSRF}}"/>
<table id="account_view" class="form">
	<tr>
		<th>First Name</th>
		<td><input type="text" name="first_name" value="{{.FirstName}}".></td>
	</tr>
	<tr>
		<th>Last Name</th>
		<td><input type="text" name="last_name" value="{{.LastName}}"/></td>
	</tr>
	<tr>
		<th>Email</th>
		<td><input type="email" name="email" value="{{.Email}}" style="width: 18em"></td>
	</tr>

	<tr><td>&nbsp;</td><td></td></tr>
	<tr>
		<th>Password</th>
		<td><input type="password" name="password" value="" style="width: 18em"/></td>
	</tr>

	<tr><td>&nbsp;</td><td></td></tr>

	<tr>
		<th>Administrator</th>
		<td><input type="checkbox" name="s1" value="s1"> View administrative area</td>
	</tr>
	<tr>
		<th>System Settings</th>
		<td><input type="checkbox" name="s2" value="s2"> Manage System settings</td>
	</tr>
	<tr>
		<th>Accounts</th>
		<td><input type="checkbox" name="s3" value="s3"> Manage Accounts</td>
	</tr>
	<tr>
		<th>Picklists</th>
		<td><input type="checkbox" name="s4" value="s4"> Manage Picklists</td>
	</tr>

	<tr><td>&nbsp;</td><td></td></tr>

{{range .CustomRoleTypes}}
	<tr>
		<th>{{.Name}}</th>
		<td><input type="checkbox" name="{{.Uid}}" value="{{.Uid}}"/> {{.Description}}</td>
	</tr>
{{end}}

	<tr><td>&nbsp;</td><td></td></tr>



	<tr><td></td><td><input type="submit" value="Create Account"></td></tr>
</table>
</form>

</div>
{{template "admin_footer" .}}
{{end}}
`
