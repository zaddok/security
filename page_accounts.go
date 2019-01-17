package security

import (
	"html/template"
	"net/http"
	"net/url"
	"sort"
)

func AccountsPage(t *template.Template, am AccessManager, siteName, siteDescription, supplimentalCss string) func(w http.ResponseWriter, r *http.Request) {
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

		if r.FormValue("new") == "create" {

			type Page struct {
				SiteName        string
				SiteDescription string
				Title           []string
				Session         Session
				Query           string
				FirstName       string
				LastName        string
				Email           string
				Feedback        []string
			}

			p := &Page{
				SiteName:        siteName,
				SiteDescription: siteDescription,
				Title:           []string{"Create new account", "Accounts"},
				Session:         session,
				Query:           r.FormValue("q"),
			}

			p.FirstName = r.FormValue("first_name")
			p.LastName = r.FormValue("last_name")
			p.Email = r.FormValue("email")

			if r.Method == "POST" {
				feedback, err := createAccountWithFormValues(am, session, r)
				if err != nil {
					ShowError(w, r, t, err, siteName)
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
			SiteName        string
			SiteDescription string
			SupplimentalCss string
			Title           []string
			Session         Session
			Query           string
			Accounts        []Person
		}

		err = r.ParseForm()
		if err != nil {
			ShowError(w, r, t, err, siteName)
			return
		}
		q := r.Form.Get("q")

		var accounts []Person = nil
		if q != "" {
			accounts, err = am.SearchPeople(q, session)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
		}

		sort.Slice(accounts, func(i, j int) bool {
			return accounts[j].GetFirstName() > accounts[i].GetFirstName()
		})

		Render(r, w, t, "accounts", &Page{siteName, siteDescription, supplimentalCss, []string{"Accounts"}, session, q, accounts})
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

	if len(warnings) == 0 {
		var pw *string = nil
		if password != "" {
			pw = &password
		}
		_, err := am.AddPerson(session.GetSite(), firstName, lastName, email, pw)
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
<a href="/z/accounts?q={{.Query}}&new=create" class="new_person">New Account</a>
</div>
{{end}}

<div class="search_layout">
{{if .Accounts}}{{else}}
<br><br><br>
{{end}}
<h1>Accounts</h1>
<div class="search">
<form method=get>
<div id="q"><input type="text" name="q" id="qi" value="{{.Query}}" placeholder="First name, Last name, or Student number"/></div>
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
		<td><a href="/z/account.details/{{.Uuid}}?q={{$.Query}}"></a></td>
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

var adminTemplate = `
{{define "admin_header"}}
<!doctype html>
<html lang="en">
        <head>
                <meta charset="utf-8">
                <title>{{range .Title}}{{.}} &mdash; {{end}} {{.SiteName}}</title>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=1.0, minimum-scale=1.0, maximum-scale=1.0, viewport-fit=cover">
				<meta name="description" content="{{.SiteDescription}}">
				<meta name="apple-mobile-web-app-title" content="{{.SiteName}}">
				<meta name="apple-mobile-web-app-capable" content="yes">
				<link rel="apple-touch-icon" href="/favicon.ico" />
				<style type="text/css">
                        @font-face { font-family: 'FontAwesome'; src: url('/font/fa-regular-400.eot'); src: url('/font/fa-regular-400.eot?#iefix') format('embedded-opentype'), url('/font/fa-regular-400.woff') format('woff'), url('/font/fa-regular-400.ttf') format('truetype'); font-weight: normal; font-style: normal }
                        @font-face { font-family: 'FontAwesomeBrands'; src: url('/font/fa-brands-400.eot'); src: url('/font/fa-brands-400.eot?#iefix') format('embedded-opentype'), url('/font/fa-brands-400.woff') format('woff'), url('/font/fa-brands-400.ttf') format('truetype'); font-weight: normal; font-style: normal }
                        @font-face { font-family: 'FontAwesomeSolid'; src: url('/font/fa-solid-900.eot'); src: url('/font/fa-solid-900.eot?#iefix') format('embedded-opentype'), url('/font/fa-solid-900.woff') format('woff'), url('/font/fa-solid-900.ttf') format('truetype'); font-weight: normal; font-style: normal }
                        @font-face { font-family: 'MaterialIcons'; src: url('/font/materialicons.eot'); src: url('/font/materialicons.eot?#iefix') format('embedded-opentype'), url('/font/materialicons.woff') format('woff'), url('/font/materialicons.ttf') format('truetype'); font-weight: normal; font-style: normal }

			html {
				overflow-x:hidden;
			}
			body {
				overflow-x:hidden;
				margin: 0;
				padding: 0;
				background: #ffffff;
				font-family: "Helvetica Neue", Helvetica, Arial;
			}

			div#header {
				text-align: center;
				margin: 0 -9999rem;
				padding: 0rem 9999rem;
				border-bottom: 0.2em solid #3e0a01;
				background-color: #6d1202;
			}
			div#logo {
				padding: 0.6em;
				background: #6d1202 url(/psc_logo_white.svg) no-repeat 0.8em 0.8em;
				background-size: 9.88em 2em;
				display: block;
				width: 9.58em;
				height: 2.3em;
				margin-right:-3em;
				/* top: 0.4em; z-index: 100; position:absolute; */
				float:left;
			}

			div#header div#buttons {
				display: inline-block;
				border-right: 0.5px solid #333;
			}
			div#buttons > span:hover {
					  background: #3e0a01;
			}
			div#buttons > span {
				display: inline-block;
				min-height: 3.5em;
				min-width: 4em;
				border-left: 0.5px solid #333;
				text-align:center;
			}
			div#header div#buttons a {
				display: inline-block;
				font-size: 0.9em;
				color: white;
				text-decoration: none;
				margin-top: 0.7em;
			}
			div#buttons a > span:before {
				font-family: FontAwesomeSolid;
				font-size: 1.6em;
				display:block;
				padding:0; margin:0;
				content: "\f0ae";
			}
			div#buttons a.s > span:before { content: "\f013"; }
			div#buttons a.a > span:before { content: "\f4fe"; }
			div#buttons a.p > span:before { content: "\f00b"; }
			div#buttons a.l > span:before { content: "\f543"; }
			div#buttons a.x > span:before { content: "\f2f1"; }
			div#content {
				padding: 1.5em;
				font-size: 0.95em;
				min-height: 20em;
				margin-left: auto;
				margin-right: auto;
				padding-left: max(1.5em, env(safe-area-inset-left));
				padding-right: max(1.5em, env(safe-area-inset-right));
			}

			@media print {
				div#header { display: none; }
			}
			@media screen and (max-width: 720px) {
				div#content {
					margin-left: 1em;
					margin-right: 1em;
				}
				div#buttons span:nth-child(6) {
					display: none;
				}
			}
			@media screen and (max-width: 650px) {
				div#buttons span:nth-child(5) {
					display: none;
				}
			}
			@media screen and (max-width: 600px) {
				div#header {
				}
			}

			h1 { font-size: 1.4em; line-height: 1.05em; color: #000; margin-top:1em; padding-top:0; margin-bottom: 0.2em; }
			h3 {
				font-size: 1.25em;
				line-height: 1.05em;
				color: #555;
				font-weight: normal;
				padding-top: 0.5em;
				margin-bottom: 0;
			}

			table {
				margin-left: 1em;
				margin-top: 1em;
				margin-bottom: 1em;
				border-collapse: collapse;
				border-bottom: 1px solid #eee;
			}
			table tr td a {
				color: black;
				text-decoration: none;
			}
			table tr td a:hover {
				color: black;
				text-decoration: underline;
			}
			table tr td,
			table tr th {
				text-align: left;
				padding: 0.2em 0.4em 0.2em 0.4em;
			}
			table tr th {
				border-top: 1px solid #eee;
				border-bottom: 1px solid #eee;
				font-weight: normal;
				color: #888
			}
			table tr:first-child:hover {
				background: #fff;
			}
			table tr:hover {
				background: #eee;
			}
			table tr td {
				vertical-align: top;
			}
			table tr th {
				vertical-align: bottom;
			}

			table#student_search_results {
				margin-left: auto;
				margin-right: auto;
				min-width: 30em;
			}
			table#subject_search_results {
				margin-left: auto;
				margin-right: auto;
				min-width: 40em;
			}
			table#course_search_results {
				margin-left: auto;
				margin-right: auto;
				min-width: 40em;
			}

			table.form {
				margin-top: 1em;
				margin-bottom: 1em;
				border-collapse: collapse;
				border-bottom: 0px;
			}
			table.form tr th {
				border-top: 0px;
				border-bottom: 0px;
				font-weight: normal;
				color: #888;
				text-align: right;
				white-space: nowrap;
			}
			table.form tr:hover {
				background: #fff;
			}

			div.search_layout {
				text-align: center
			}
			div.search {
				padding: 0.3em 0.3em 0.3em 0.9em;
				text-align: left;
				background: #eee;
				width: 70%;
				margin-left: auto;
				margin-right: auto;
				border-radius: 20px; -webkit-border-radius: 20px; -moz-border-radius: 20px;
				padding-right: 1em;
				white-space: nowrap;
			}
			div.search div#q:before {
				content: "\f002";
				font-family: FontAwesomeSolid;
                                color: grey;
                                padding-right: 0.4em;
				font-size: 1.2em;
			}
			div.search #q input {
				font-size: 1.1em;
				width: 93%;
				background: #f2f2f2;
				font-size: 1.1em;
				border: 0px;
				padding-left: 0.5em;
				border-radius: 0.5em; -webkit-border-radius: 0.5em; -moz-border-radius: 0.5em;
			}
			a.jumpto::before {
				content: "\f0a9";
				font-family: FontAwesomeSolid;
                                color: #ccc;
                                padding-right: 0.4em;
				font-size: 1.2em;
			}
			a.jumpto:hover::before {
                                color: #888;
				text-decoration: none !important;
			}

			#subject_enrolment_list .audit td {
				color: #bbb;
			}
			#subject_enrolment_list tr td:first-child {
				text-align: right;
			}
			#subject_enrolment_list .cca {
				font-size: 0.78em;
				color: #999;
			}

			div#actions {
				text-align:right;
				margin: -1.2em 0 0.5em 0;
			}
			div#actions a {
				text-decoration: none;
				display:inline-block;
				padding: 0.3em 0.6em 0.3em 0.6em;
			}
			div#actions a:hover {
				border-radius: 0.5em;
				background: #eef;
			}
			div#actions a::before {
				font-family: FontAwesomeSolid;
				padding-right: 0.3em;
				padding-left: 0.6em;
			}
			div#actions a.note::before {
				content: "\f46c";
			}
			div#actions a.edit::before {
				content: "\f044";
			}
			div#actions a.history::before {
				content: "\f543";
			}
			div#actions a.new_person::before {
				font-family: MaterialIcons;
				content: "\e7fe";
				display: inline-block;
				padding-bottom: 0.15em;
				vertical-align: middle;
				font-size: 1.1em;
				opacity: 0.7;
			}

			div#footer {
				text-align: center;
				font-size: 0.8rem;
				color: #999;
				clear: both;
				padding: 1em;
			}
			div#footer a {
				color: #777;
			}

			a.back {
				text-decoration: none;
				color: #058cff;
				padding: 0.3em 0.6em 0.3em 0.3em;
			}
			a.back:hover {
				text-decoration: underline;
				color: #0476d7;
				background: #d0e8ff;
				border-radius: 0.5em;
			}
			a.back::visited {
				text-decoration: none;
				color: #058cff;
			}
			a.back::before {
				content: "\f137";
				font-family: FontAwesomeSolid;
				opacity: 0.5;
				padding-right: 0.3em;
				font-size: 0.9em;
				text-decoration: none !important;
			}
			a.back::before:hover {
				text-decoration: none !important;
			}

			#footer a::before {
				font-family: FontAwesome;
				opacity: 0.5;
				display:inline-block;
			}
			#footer a[href^="/"]::before {
				font-family: FontAwesomeSolid;
				margin-left: 0.7em;
				content: "\f015";
				padding-right:0.3em;
			}
			#footer a[href^="/feedback"]::before {
				font-family: FontAwesome;
				margin-left: 0.7em;
				content: "\f075";
				padding-right:0.3em;
			}
			#footer a[href^="/signout"]::before {
				font-family: FontAwesomeSolid;
				margin-left: 0.7em;
				content: "\f2f5";
				padding-right:0.3em;
			}

			div.feedback {
				padding: 0.4em 1em 0.4em 0.7em;
				margin: 1em 0em 1em 0em;
				clear: both;
				background: #b9deff;
				border-radius: 0.6em;
				border: 1px solid #a9ceef;
			}
			div.feedback::before {
				float:left;
				display: inline-block;
				font-family: FontAwesomeSolid;
				opacity 0.45;
				margin-top: -0.05em;
				font-size: 1.2em;
				content: '\f06a';
			}
			div.feedback ul, div.feedback p {
				margin: 0 0 0 2em;
				padding: 0;
				opacity: 0.7;
			}
			div.feedback ul li {
				list-style-type: none;
			}

			div.info { color: #024; }
			div.info::before { color: #68c; content: '\f05a' }

			div.warning, div.warning::before { color: #420; background: #ffdeb9; border-color: #efcea9; }
			div.warning::before { content: '\f071'; color: #a86; }

			div.error, div.error::before { color: #400; background: #ffb9b9; border-color: #efa9a9; }
			div.error::before { color: #844; opacity: 0.7;}

			div.success, div.success::before { color: #041; background: #b9ffde; border-color: #aec; }
			div.success::before { content: '\f058'; color: #7b6; opacity: 0.7; }
                </style>
</head>
<body>
	<div id="logo"></div>
	<div id="header">
		<div id="buttons">
			<span><a href="/z/accounts" class="a"><span>Accounts</span></a></span><span><a href="/z/picklist" class="p"><span>Picklists</span></a></span><span><a href="/z/audit" class="l"><span>Audit</span></a></span><span><a href="/z/connectors" class="x"><span>Connector</span></a></span><span><a href="/z/settings" class="s"><span>Settings</span></a></span>
		</div>
	</div>
	<div id="content">
{{end}}



{{define "admin_footer"}}
        </div>
        <div id="footer">
Currently signed in as {{.Session.FirstName}} {{.Session.LastName}}. <a href="/feedback">Feedback</a> <a href="/">Home</a> <a href="/signout">Sign out</a>.
        </div>
</body>
</html>
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

<form method="post"><input type="hidden" name="q" value="{{.Query}}"/>
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

	<tr><td></td><td><input type="submit" value="Create Account"></td></tr>
</table>
</form>

</div>
{{template "admin_footer" .}}
{{end}}
`
