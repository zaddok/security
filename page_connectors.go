package security

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ConfSet struct {
	English   string
	FieldName string
	Value     string
	Type      string
}

func ConnectorsPage(t *template.Template, am AccessManager, siteName, siteDescription, siteCss string) func(w http.ResponseWriter, r *http.Request) {

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
		if !session.HasRole("c6") {
			ShowErrorForbidden(w, r, t, siteName)
			return
		}
		AddSafeHeaders(w)

		q := r.FormValue("log")
		if q != "" {
			type Page struct {
				SiteName        string
				SiteDescription string
				Title           []string
				Session         Session
				LogEntry        []LogEntry
			}

			entries, err := am.GetLogCollection(q, session)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
			Render(r, w, t, "connector_log", &Page{siteName, siteDescription, []string{"Reports"}, session, entries})
			return
		}

		collections, cerr := am.GetRecentLogCollections(session)
		if err != nil {
			ShowError(w, r, t, cerr, siteName)
			return
		}

		type ConfInfo struct {
			ScheduledConnector *ScheduledConnector
			ConnectorInfo      *ConnectorInfo
		}
		type Page struct {
			SiteName               string
			SiteDescription        string
			Title                  []string
			Session                Session
			Connectors             []*ConnectorInfo
			ScheduledConnectors    []*ScheduledConnector
			ScheduledConnectorInfo []*ConfInfo
			LogCollection          []LogCollection
		}

		if r.FormValue("delete") != "" {
			err := am.DeleteScheduledConnector(r.FormValue("delete"), session)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
		}

		if r.FormValue("pause") != "" {
			s, err := am.GetScheduledConnector(r.FormValue("pause"), session)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
			if s == nil {
				ShowErrorNotFound(w, r, t, siteName)
				return
			}
			s.Disabled = !s.Disabled
			err = am.UpdateScheduledConnector(s, session)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
		}

		if r.FormValue("run") != "" {
			s, err := am.GetScheduledConnector(r.FormValue("run"), session)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
			if s == nil {
				fmt.Printf("Scheduled connector not found. Site: %s UUID: %s\n", session.GetSite(), r.FormValue("run"))
				ShowErrorNotFound(w, r, t, siteName)
				return
			}

			// Task queue is only available on appengine. Handle tasks differently on localhost
			if session.Site() == "localhost" || strings.HasPrefix(session.Site(), "dev") {
				// When on DEV
				am.Notice(session, `connector`, "Cannot run connectors in development environment.")
				found := am.GetConnectorInfoByLabel(s.Label)
				if found != nil {

					if found.Run != nil {
						err := found.Run(am, s, session)
						if err != nil {
							am.Error(session, `connector`, "Failed executing connector %s %v", s.Label, err)
						} else {
							am.Debug(session, `connector`, "Executed connector %s successfully", s.Label)
						}
					}
				}

			} else {
				// When not on DEV
				_, err = am.CreateTask("connector", s.Uuid)
				if err == nil {
					now := time.Now()
					s.LastRun = &now
					err = am.UpdateScheduledConnector(s, session)
					if err != nil {
						w.Write([]byte("AAARGH!!!! " + err.Error() + "\n"))
					}
					http.Redirect(w, r, "/z/connectors", http.StatusSeeOther)
					return
				} else {
					ShowError(w, r, t, err, siteName)
					return
				}
			}
		}

		if r.FormValue("edit") != "" {
			connector, err := am.GetScheduledConnector(r.FormValue("edit"), session)
			if err != nil {
				ShowError(w, r, t, err, siteName)
				return
			}
			if connector == nil {
				ShowErrorNotFound(w, r, t, siteName)
				return
			}
			var cType *ConnectorInfo = nil
			for _, i := range am.GetConnectorInfo() {
				if connector.Label == i.Label {
					cType = i
					break
				}
			}

			type Page struct {
				SiteName           string
				SiteDescription    string
				Title              []string
				Session            Session
				ConnectorType      *ConnectorInfo
				ScheduledConnector *ScheduledConnector
				ExternalSystem     ExternalSystem
				Config             []*ConfSet
				Feedback           []string
			}

			p := &Page{
				SiteName:           siteName,
				SiteDescription:    siteDescription,
				Title:              []string{"Connector"},
				Session:            session,
				ConnectorType:      cType,
				ScheduledConnector: connector,
			}

			if cType.ExternalSystemPicker == true {
				p.ExternalSystem, err = am.GetExternalSystem(p.ScheduledConnector.ExternalSystemUuid, session)
				if err != nil {
					am.Error(session, `connector`, "Scheduled Connector '%s' references unknown ExternalSystemUuid '%s'", p.ScheduledConnector.Uuid, p.ScheduledConnector.ExternalSystemUuid)
					ShowErrorNotFound(w, r, t, siteName)
					return
				}
			}
			for _, x := range cType.Config {
				cs := &ConfSet{
					English:   x[0],
					FieldName: "cv_" + strings.ToLower(strings.Replace(x[0], " ", "_", -1)),
				}
				if len(x) > 1 {
					cs.Type = x[1]
				}
				cs.Value = p.ScheduledConnector.GetConfig(x[0])
				//cs.Value = r.FormValue(cs.FieldName)
				p.Config = append(p.Config, cs)
			}

			if r.Method == "POST" {
				hour, _ := strconv.Atoi(r.FormValue("hour"))
				day, _ := strconv.Atoi(r.FormValue("day"))
				connector.Hour = hour
				connector.Day = day
				/*
					scheduled := &ScheduledConnector{
						ExternalSystemUuid: r.FormValue("external_system_uuid"),
						Label:              label,
						Frequency:          r.FormValue("frequency"),
						Hour:               hour,
						Day:                day,
					}*/
				for _, x := range cType.Config {
					connector.SetConfig(x[0], r.FormValue("cv_"+strings.ToLower(strings.Replace(x[0], " ", "_", -1))))
				}
				err := am.UpdateScheduledConnector(connector, session)
				if err != nil {
					ShowError(w, r, t, err, siteName)
					return
				}
				http.Redirect(w, r, "/z/connectors", http.StatusSeeOther)
			} else {
				Render(r, w, t, "connector_edit", p)
				return
			}
		}

		label := r.FormValue("add")
		if label != "" {
			cType := am.GetConnectorInfoByLabel(label)

			if cType != nil {
				var feedback []string
				type Page struct {
					SiteName        string
					SiteDescription string
					Title           []string
					Session         Session
					Connector       *ConnectorInfo
					ExternalSystems []ExternalSystem
					Uuid            string
					Frequency       string
					Hour            int
					Day             int
					Config          []*ConfSet
					Feedback        []string
				}
				hour, _ := strconv.Atoi(r.FormValue(`hour`))
				day, _ := strconv.Atoi(r.FormValue(`day`))
				p := &Page{
					SiteName:        siteName,
					SiteDescription: siteDescription,
					Title:           []string{"Connector"},
					Session:         session,
					Connector:       cType,
					Uuid:            r.FormValue(`uuid`),
					Hour:            hour,
					Day:             day,
					Feedback:        feedback,
				}
				if cType.ExternalSystemPicker == true {
					current, err := am.GetExternalSystemsByType(cType.SystemType, session)
					if err != nil {
						ShowError(w, r, t, err, siteName)
						return
					}
					p.ExternalSystems = current
				}
				if len(p.ExternalSystems) > 0 && p.Uuid == "" {
					p.Uuid = p.ExternalSystems[0].Uuid()
				}
				for _, x := range cType.Config {
					cs := &ConfSet{
						English:   x[0],
						FieldName: "cv_" + strings.ToLower(strings.Replace(x[0], " ", "_", -1)),
					}
					if len(x) > 1 {
						cs.Type = x[1]
					}
					cs.Value = r.FormValue(cs.FieldName)
					p.Config = append(p.Config, cs)
				}

				if r.Method == "POST" {
					hour, _ := strconv.Atoi(r.FormValue("hour"))
					day, _ := strconv.Atoi(r.FormValue("day"))
					scheduled := &ScheduledConnector{
						ExternalSystemUuid: r.FormValue("external_system_uuid"),
						Label:              label,
						Frequency:          r.FormValue("frequency"),
						Hour:               hour,
						Day:                day,
					}
					for _, x := range cType.Config {
						kv := KeyValue{
							Key:   strings.ToLower(strings.Replace(x[0], " ", "_", -1)),
							Value: r.FormValue("cv_" + strings.ToLower(strings.Replace(x[0], " ", "_", -1))),
						}
						scheduled.Config = append(scheduled.Config, &kv)
					}
					err := am.AddScheduledConnector(scheduled, session)
					if err != nil {
						ShowError(w, r, t, err, siteName)
						return
					}
					http.Redirect(w, r, "/z/connectors", http.StatusSeeOther)
				} else {
					Render(r, w, t, "connector_add", p)
					return
				}
			}
		}

		scheduled, err := am.GetScheduledConnectors(session)
		if err != nil {
			ShowError(w, r, t, err, siteName)
			return
		}

		var confinfo []*ConfInfo
		for _, sc := range scheduled {
			c := &ConfInfo{
				ScheduledConnector: sc,
			}
			for _, ci := range am.GetConnectorInfo() {
				if ci.Label == sc.Label {
					c.ConnectorInfo = ci
					break
				}
			}
			if c.ConnectorInfo == nil {
				c.ConnectorInfo = &ConnectorInfo{Name: "error"}
			}
			confinfo = append(confinfo, c)
		}

		p := &Page{
			siteName,
			siteDescription,
			[]string{"Connectors"},
			session,
			am.GetConnectorInfo(),
			scheduled,
			confinfo,
			collections,
		}

		Render(r, w, t, "connectors", p)
	}
}

var connectorAddTemplate = `
{{define "connector_add"}}
{{template "admin_header" .}}
<div style="margin-top: -0.7rem"><a class="back" href="/z/connectors">Back</a></div>

<style type="text/css">
#editform table {
	margin-left:auto;
	margin-right:auto;
}
#editform p {
	margin-top: 0;
	text-align:center;
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

table.form tr td:first-child {
	padding-left: 1em;
}
h3 {
	padding-bottom:1em;
	margin-left: -2em;
}
h3::before {
        content: "\f017";
        font-family: FontAwesome;
        opacity: 0.3;
        padding-right: 0.3em;
        font-size: 0.9em;
        text-decoration: none !important;
}
h3.schedule::before {
        content: "\f017";
}
h3.external::before {
        font-family: FontAwesomeSolid;
        content: "\f1c0";
}
h3.config::before {
        content: "\f1de";
        font-family: FontAwesomeSolid;
}

td a.add {
	color: #aca;
	text-decoration: none;
	display: block;
	padding-bottom: 0.8em;
}
td a.add:hover {
	text-decoration: none;
	color: #8a8;
}
td a.add::before {
	content: "\f055";
	font-family: FontAwesomeSolid;
	opacity: 0.3;
	padding-right: 0.3em;
	padding-left: 0.4em;
	font-size: 0.9em;
	text-decoration: none !important;
}
</style>

<div id="editform">
<h1>Add Connector: {{.Connector.Name}}</h1>
<p>{{.Connector.Description}}</p>

{{if .Feedback}}<div class="feedback error">{{if eq 1 (len .Feedback)}}<p>{{index .Feedback 0}}</p>{{else}}<ul>{{range .Feedback}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<form method="post">
<input type="hidden" name="add" value="{{.Connector.Label}}" />
<input type="hidden" name="csrf" value="{{.Session.CSRF}}"/>
<table id="connector_add" class="form">
{{if .Connector.ExternalSystemPicker}}
	<tr><td colspan="2"><h3 class="external">External System</h3></td></tr>
	<tr>
		<td colspan="2"><select name="external_system_uuid">
		<option value="">Select system to connect with</option>
{{range .ExternalSystems}}
		<option value="{{.Uuid}}"{{if eq $.Uuid .Uuid}}selected{{end}}>{{.Describe}}</option>
{{end}}
		</select> <a href="/z/external.system.create?type={{.Connector.SystemType}}&connector={{.Connector.Label}}" class="add">Add External System</a>
		</td>
	</tr>
	<tr><td>&nbsp;</td><td></td></tr>
{{end}}

	<tr><td colspan="2"><h3 class="schedule">Schedule</h3></td></tr>
	<tr><td>Frequency</td><td style="vertical-align:middle">
		<input type="radio" name="frequency" value="daily"{{if eq .Frequency "daily"}} checked{{end}}> Daily <select name="hour">
<option value="7"{{if eq .Hour 7}} selected{{end}}>7am</option>
<option value="8"{{if eq .Hour 8}} selected{{end}}>8am</option>
<option value="9"{{if eq .Hour 9}} selected{{end}}>9am</option>
<option value="10"{{if eq .Hour 10}} selected{{end}}>10am</option>
<option value="11"{{if eq .Hour 11}} selected{{end}}>11am</option>
<option value="12"{{if eq .Hour 12}} selected{{end}}>12pm</option>
<option value="13"{{if eq .Hour 13}} selected{{end}}>1pm</option>
<option value="14"{{if eq .Hour 14}} selected{{end}}>2pm</option>
<option value="15"{{if eq .Hour 15}} selected{{end}}>3pm</option>
<option value="16"{{if eq .Hour 16}} selected{{end}}>4pm</option>
<option value="17"{{if eq .Hour 17}} selected{{end}}>5pm</option>
<option value="18"{{if eq .Hour 18}} selected{{end}}>6pm</option>
<option value="19"{{if eq .Hour 19}} selected{{end}}>7pm</option>
<option value="20"{{if eq .Hour 20}} selected{{end}}>8pm</option>
<option value="21"{{if eq .Hour 21}} selected{{end}}>9pm</option>
		</select><br>
		<input type="radio" name="frequency" value="hourly" {{if eq .Frequency "hourly"}}checked{{end}}> Hourly</td></tr>


	<tr><td>&nbsp;</td><td></td></tr>
	<tr><td colspan="2"><h3 class="config">Configuration</h3></td></tr>
{{range .Config}}{{if eq "-" .English}}
	<tr><td>&nbsp;</td><td></td></tr>
{{else}}
	<tr>
		<th>{{.English}}</th>
		<td>
{{if eq .Type "bool"}}
			<input type="checkbox" name="{{.FieldName}}" value="true"{{if eq .Value "true"}} checked{{end}}>
{{else}}
			<input type="text" name="{{.FieldName}}" value="{{.Value}}">
{{end}}
		</td>
	</tr>
{{end}}
{{end}}

	<tr><td>&nbsp;</td><td></td></tr>
	<tr><td></td><td><input type="submit" value="Add Connector"></td></tr>
</table>
</form>

{{template "admin_footer" .}}
{{end}}
`

var connectorEditTemplate = `
{{define "connector_edit"}}
{{template "admin_header" .}}
<div style="margin-top: -0.7rem"><a class="back" href="/z/connectors">Back</a></div>

<style type="text/css">
#editform table {
	margin-left:auto;
	margin-right:auto;
}
#editform p {
	margin-top: 0;
	text-align:center;
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

table.form tr td:first-child {
	padding-left: 1em;
}
h3 {
	padding-bottom:1em;
	margin-left: -2em;
}
h3::before {
        content: "\f017";
        font-family: FontAwesome;
        opacity: 0.3;
        padding-right: 0.3em;
        font-size: 0.9em;
        text-decoration: none !important;
}
h3.schedule::before {
        content: "\f017";
}
h3.external::before {
        font-family: FontAwesomeSolid;
        content: "\f1c0";
}
h3.config::before {
        content: "\f1de";
        font-family: FontAwesomeSolid;
}

</style>

<div id="editform">
<h1>Edit Connector: {{.ConnectorType.Name}}</h1>
<p>{{.ConnectorType.Description}}</p>

{{if .Feedback}}<div class="feedback error">{{if eq 1 (len .Feedback)}}<p>{{index .Feedback 0}}</p>{{else}}<ul>{{range .Feedback}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}

<form method="post">
<input type="hidden" name="edit" value="{{.ScheduledConnector.Uuid}}" />
<input type="hidden" name="csrf" value="{{.Session.CSRF}}"/>

<table id="connector_edit" class="form">
{{if .ConnectorType.ExternalSystemPicker}}
	<tr><td colspan="2"><h3 class="external">External System</h3></td></tr>
	<tr>
		<td colspan="2"><input type="hidden" name="external_system_uuid" value="{{.ExternalSystem.Uuid}}" />
		{{.ExternalSystem.Describe}}
		</td>
	</tr>
	<tr><td>&nbsp;</td><td></td></tr>
{{end}}

	<tr><td colspan="2"><h3 class="schedule">Schedule</h3></td></tr>
	<tr><td>Frequency</td><td style="vertical-align:middle">
		<input type="radio" name="frequency" value="daily"{{if eq .ScheduledConnector.Frequency "daily"}} checked{{end}}> Daily at <select name="hour">
<option value="7"{{if eq .ScheduledConnector.Hour 7}} selected{{end}}>7am</option>
<option value="8"{{if eq .ScheduledConnector.Hour 8}} selected{{end}}>8am</option>
<option value="9"{{if eq .ScheduledConnector.Hour 9}} selected{{end}}>9am</option>
<option value="10"{{if eq .ScheduledConnector.Hour 10}} selected{{end}}>10am</option>
<option value="11"{{if eq .ScheduledConnector.Hour 11}} selected{{end}}>11am</option>
<option value="12"{{if eq .ScheduledConnector.Hour 12}} selected{{end}}>12pm</option>
<option value="13"{{if eq .ScheduledConnector.Hour 13}} selected{{end}}>1pm</option>
<option value="14"{{if eq .ScheduledConnector.Hour 14}} selected{{end}}>2pm</option>
<option value="15"{{if eq .ScheduledConnector.Hour 15}} selected{{end}}>3pm</option>
<option value="16"{{if eq .ScheduledConnector.Hour 16}} selected{{end}}>4pm</option>
<option value="17"{{if eq .ScheduledConnector.Hour 17}} selected{{end}}>5pm</option>
<option value="18"{{if eq .ScheduledConnector.Hour 18}} selected{{end}}>6pm</option>
<option value="19"{{if eq .ScheduledConnector.Hour 19}} selected{{end}}>7pm</option>
<option value="20"{{if eq .ScheduledConnector.Hour 20}} selected{{end}}>8pm</option>
<option value="21"{{if eq .ScheduledConnector.Hour 21}} selected{{end}}>9pm</option>
		</select><br>
		<input type="radio" name="frequency" value="hourly"{{if eq .ScheduledConnector.Frequency "hourly"}} checked{{end}}> Hourly<br>
	</td></tr>

	<tr><td>&nbsp;</td><td></td></tr>
	<tr><td colspan="2"><h3 class="config">Configuration</h3></td></tr>
{{range .Config}}{{if eq "-" .English}}
	<tr><td>&nbsp;</td><td></td></tr>
{{else}}
	<tr>
		<th>{{.English}}</th>
		<td>
{{if eq .Type "bool"}}
			<input type="checkbox" name="{{.FieldName}}" value="true"{{if eq .Value "true"}} checked{{end}}>
{{else}}
			<input type="text" name="{{.FieldName}}" value="{{.Value}}">
{{end}}
		</td>
	</tr>
{{end}}
{{end}}

	<tr><td>&nbsp;</td><td></td></tr>
	<tr><td></td><td><input type="submit" value="Update Connector"></td></tr>
</table>
</form>

{{template "admin_footer" .}}
{{end}}
`

var connectorTemplate = `
{{define "connectors"}}
{{template "admin_header" .}}

<style type="text/css">
li.dir0::before,
li.dir1::before,
li.dir-1::before {
	font-family: FontAwesomeSolid;
	padding-right: 0.3em;
	opacity: 0.6;
}
li.dir0::before {
	content: "\f362";
}
li.dir1::before {
	content: "\f30b";
}
li.dir-1::before {
	content: "\f30a";
}

table.connectors td a,
table.connectors td a:visited {
	font-size: 0.9em;
	color: #aaa;
}
table.connectors td a::before {
	font-family: FontAwesomeSolid;
	opacity: 0.5;
	padding-right: 0.3em;
	padding-left: 0.6em;
}
table.connectors td a.pause::before {
	content: "\f04c";
}
table.connectors td a.run::before {
	content: "\f2f1";
}
table.connectors td a.edit::before {
	content: "\f044";
}
table.connectors td a.delete::before {
	content: "\f2ed";
	font-family: FontAwesome;
}

h1 {
	text-align: center;
}
#scheduled_connectors {
	margin-left: auto;
	margin-right: auto;
}
tr.disabled td {
	opacity: 0.5;
}
</style>

<h1>Active Connectors</h1>
{{if .ScheduledConnectors}}
<table class="connectors" id="scheduled_connectors">
<thead>
	<th></th>
	<th>Type</th>
	<th></th>
	<th>Hour</th>
	<th>Type</th>
	<th>Last Run</th>
	<th></th>
</thead>
<tbody>
{{range .ScheduledConnectorInfo}}
<tr{{if .ScheduledConnector.Disabled}} class="disabled"{{else}} class="enabled"{{end}}>
<td style="padding:0;"><img src="{{.ConnectorInfo.SystemIcon}}" style="width:1.3em; height: 1.3em;margin-top:0.23em" /></td>
	<td style="vertical-align:middle">{{.ConnectorInfo.Name}}</td>
	<td style="vertical-align:middle">{{.ScheduledConnector.Description}}</td>
	<td style="vertical-align:middle">{{if eq .ScheduledConnector.Frequency "hourly"}}Hourly{{end}}{{if eq .ScheduledConnector.Frequency "daily"}}Daily{{end}}{{if eq .ScheduledConnector.Frequency "weekly"}}Weekly{{end}}</td>
	<td style="vertical-align:middle; text-align:center">{{if eq .ScheduledConnector.Frequency "daily"}}{{ampm .ScheduledConnector.Hour}}{{end}}{{if eq .ScheduledConnector.Frequency "weekly"}}((.ScheduledConnector.Day}} {{ampm .ScheduledConnector.Hour}}{{end}}</td>
	<td style="vertical-align:middle">{{.ScheduledConnector.LastRun | log_date}}</td>
	<td style="vertical-align:middle">
		<a class="pause" href="/z/connectors?pause={{.ScheduledConnector.Uuid}}"></a>
{{if ne .ScheduledConnector.Label "formsite-student-course-import"}}
		<a class="edit" href="/z/connectors?edit={{.ScheduledConnector.Uuid}}"></a>
{{else}}
		<a class="edit" href="/z/connector/formsite.map?uuid={{.ScheduledConnector.Uuid}}"></a>
{{end}}
		<a class="run" href="/z/connectors?run={{.ScheduledConnector.Uuid}}"></a>
		<a class="delete" href="/z/connectors?delete={{.ScheduledConnector.Uuid}}"></a>
	</td>
</tr>
{{end}}
</tbody>
</table>

<script src='/tablesort.js'></script>
<script>new Tablesort(document.getElementById('scheduled_connectors'));</script>

{{else}}
<p>There are no connectors scheduled to run. You can configure scheduled connectors below.</p>
{{end}}

<h3>Available Connectors</h3>
<ul class="connectors" style="list-style:none">
{{range .Connectors}}
<li class="dir{{.Direction}}"><img src="{{.SystemIcon}}" style="width:1.3em; height: 1.3em" /> {{.Name}} 
{{if ne .Label "formsite-student-course-import"}}<a href="/z/connectors?add={{.Label}}">Add</a>{{else}}<a href="/z/connector/formsite.add1?add={{.Label}}">Add</a>{{end}}
</li>
{{end}}
</ul>

<h3>Recent Connector Activity</h3>
<ul>
{{range .LogCollection}}
<li><a href="/z/connectors?log={{.Uuid}}">{{.Began | log_date}} {{.Component}}</a></li>
{{end}}
</ul>

{{template "admin_footer" .}}
{{end}}

{{define "connector_log"}}
{{template "admin_header" .}}
<div style="margin-top: -0.7rem"><a class="back" href="/z/connectors">Back</a></div>

<style type="text/css">
tr.DEBUG td {
	color: #aaa;
}
tr.WARN td,
tr.ERROR td {
	color: #844;
}
tr td:first-child {
	white-space: nowrap;
}
</style>

<h1>Connector Log: ({{len .LogEntry}} lines)</h1>

<table>
{{range .LogEntry}}
<tr class="{{.Level}}">
	<td>{{.Recorded | log_date}}</td>
	<td>{{.Level}}</td>
	<td>{{.Message}}</td>
</tr>
{{end}}
</table>

{{template "admin_footer" .}}
{{end}}
`
