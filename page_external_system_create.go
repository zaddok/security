package security

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

type ConfSet struct {
	English   string
	FieldName string
	Value     string
}

func ExternalSystemCreatePage(t *template.Template, am AccessManager, siteName, siteDescription, siteCss string) func(w http.ResponseWriter, r *http.Request) {

	type Page struct {
		SiteName        string
		SiteDescription string
		Title           []string
		Session         Session
		SystemType      string
		Uuid            string
		ExternalSystem  *ExternalSystem
		Feedback        []string
		Config          []*ConfSet
		ConnectorLabel  string
	}

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
		if !session.HasRole("c6") && !session.HasRole("s1") {
			ShowErrorForbidden(w, r, t, siteName)
			return
		}
		AddSafeHeaders(w)

		p := &Page{
			SiteName:        siteName,
			SiteDescription: siteDescription,
			Title:           []string{"Create new external system connection", "External Systems"},
			Session:         session,
			Uuid:            r.FormValue(`uuid`),
			SystemType:      r.FormValue(`type`),
			ConnectorLabel:  r.FormValue(`connector`),
		}
		if p.SystemType == `Mailchimp` {
			p.Config = append(p.Config, &ConfSet{"Mailchimp API Key", "mailchimp.key", ""})
		}
		if p.SystemType == `Moodle` {
			p.Config = append(p.Config, &ConfSet{"Moodle URL", "moodle.url", ""})
			p.Config = append(p.Config, &ConfSet{"Moodle API Key", "moodle.key", ""})
		}
		if p.SystemType == `Formsite` {
			p.Config = append(p.Config, &ConfSet{"Formsite URL", "formsite.url", ""})
			p.Config = append(p.Config, &ConfSet{"Formsite API Key", "formsite.key", ""})
		}
		if p.SystemType == `GoogleSheets` {
			p.Config = append(p.Config, &ConfSet{"Client Secret", "client.secret", ""})
		}

		if r.Method == "POST" {
			es, feedback, err := createExternalSystemWithFormValues(am, session, r, p.Config)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
			if len(feedback) == 0 && es != nil {
				// Saved with no errors
				if p.SystemType == "Formsite" {
					http.Redirect(w, r, "/z/connector/formsite.add1?&external_system_uuid="+es.Uuid(), http.StatusSeeOther)
				} else {
					http.Redirect(w, r, "/z/connectors?add="+url.QueryEscape(r.FormValue("connector"))+"&uuid="+es.Uuid(), http.StatusSeeOther)
				}
				return
			}
			p.Feedback = feedback
		}

		// Not saved, show creation form, with feedback if needed
		Render(r, w, t, "external_system_create", p)

		return
	}
}

// If /account.details/ detects some posted data, we can do a account update.
func createExternalSystemWithFormValues(am AccessManager, session Session, r *http.Request, conf []*ConfSet) (ExternalSystem, []string, error) {
	var warnings []string

	var config []KeyValue
	etype := r.FormValue(`type`)
	for _, i := range conf {
		val := strings.TrimSpace(r.FormValue(i.FieldName))
		if val != "" {
			config = append(config, KeyValue{i.FieldName, val})
		}
	}

	// If data is all in order, create it

	if len(warnings) == 0 {
		es, err := am.AddExternalSystem(etype, config, session)
		fmt.Printf("external system add %v %s %v\n", es, es.Uuid(), err)
		return es, warnings, err
	} else {
		return nil, warnings, nil
	}
}

var externalSystemCreateTemplate = `
{{define "external_system_create"}}
{{template "admin_header" .}}

<style type="text/css">
#editform table {
	margin-left:auto;
	margin-right:auto;
}
#editform h1 {
	text-align:center;
}
#editform p {
	text-align:center;
	margin-bottom: 2em;
}
#editform input {
	font-size: 1rem;
}
#editform table th {
	vertical-align:top;
}

</style>
<div style="margin-top: -0.7rem"><a class="back" href="/z/connectors?add={{.ConnectorLabel}}">Back</a></div>

{{if .Feedback}}<div class="feedback error">{{if eq 1 (len .Feedback)}}<p>{{index .Feedback 0}}</p>{{else}}<ul>{{range .Feedback}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<div id="editform">
<h1>Add External System: {{.SystemType}}</h1>

<p>This form is used to establish the connection details of an external system.</p>

<form method="post">
<input type="hidden" name="type" value="{{.SystemType}}"/>
<input type="hidden" name="connector" value="{{.ConnectorLabel}}"/>
<input type="hidden" name="csrf" value="{{.Session.GetCSRF}}"/>
<table id="course_edit" class="form">
	<tr>
		<th>System Type</th>
		<td>{{.SystemType}}</td>
	</tr>
	<tr><td>&nbsp;</td></tr>
{{range .Config}}
	<tr>
		<th>{{.English}}</th>
		<td><input type="text" name="{{.FieldName}}" value="{{.Value}}"></td>
	</tr>
{{end}}

	<tr><td>&nbsp;</td></tr>
	<tr><td></td><td><input type="submit" value="Create New External System"></td></tr>
</table>
</form>

</div>
{{template "admin_footer" .}}
{{end}}
`
