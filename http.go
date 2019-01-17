package security

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/zaddok/log"
)

var COOKIE_DAYS = 365

// Register pages specific to the security package
func RegisterHttpHandlers(siteName, siteDescription, siteCss string, am AccessManager, defaultTimezone *time.Location, log log.Log) error {

	st := template.New("page")
	fm := template.FuncMap{
		"safe": func(s string) template.CSS {
			return template.CSS(s)
		},
		"log_date": func(t time.Time) string {
			return t.In(defaultTimezone).Format("2006-01-02 15:04")
		},
		"lookup": func(site, category, code string) (template.HTML, error) {
			i, err := am.PicklistStore().GetPicklistItem(site, category, code)
			if err != nil {
				return template.HTML(""), err
			}
			if i == nil {
				return template.HTML("Unknown (" + code + ")"), nil
			}
			return template.HTML(i.GetValue()), nil
		},
	}
	st = st.Funcs(fm)
	for i, page := range []string{
		ActivateTemplate,
		AdminTemplate,
		accountsTemplate,
		accountHistoryTemplate,
		accountDetailsTemplate,
		accountCreateTemplate,
		ErrorTemplates,
		ForgotTemplate,
		ResetPasswordTemplate,
		SecurityHeader,
		SignupTemplate,
		settingsTemplate,
		settingEditTemplate,
	} {
		var err error
		st, err = st.Parse(page)
		if err != nil {
			log.Error("Failed parsing security template %d. %v", i, err)
			return err
		}
	}

	http.HandleFunc("/signin", SigninPage(st, am, siteName, siteDescription, siteCss))
	http.HandleFunc("/signout", SignoutPage(st, am, siteName, siteDescription))
	http.HandleFunc("/signup", SignupPage(st, am, siteName, siteDescription, siteCss))
	http.HandleFunc("/forgot/", ForgotPage(st, am, siteName, siteDescription, siteCss))
	http.HandleFunc("/activate/", ActivatePage(st, am, siteName, siteDescription, siteCss))
	http.HandleFunc("/reset.password/", ResetPasswordPage(st, am, siteName, siteDescription, siteCss))
	http.HandleFunc("/z/accounts", AccountsPage(st, am, siteName, siteDescription, siteCss))
	http.HandleFunc("/z/account.details/", AccountDetailsPage(st, am, siteName, siteDescription, siteCss))
	http.HandleFunc("/z/settings", SettingsPage(st, am, siteName, siteDescription, siteCss))

	http.HandleFunc("/font/fa-regular-400.eot", BinaryFile(&FAregularEOT, 604800))
	http.HandleFunc("/font/fa-regular-400.ttf", BinaryFile(&FAregularTTF, 604800))
	http.HandleFunc("/font/fa-regular-400.woff", BinaryFile(&FAregularWOFF, 604800))

	http.HandleFunc("/font/fa-brands-400.eot", BinaryFile(&FAbrandsEOT, 604800))
	http.HandleFunc("/font/fa-brands-400.ttf", BinaryFile(&FAbrandsTTF, 604800))
	http.HandleFunc("/font/fa-brands-400.woff", BinaryFile(&FAbrandsWOFF, 604800))

	http.HandleFunc("/font/fa-solid-900.eot", BinaryFile(&FAsolidEOT, 604800))
	http.HandleFunc("/font/fa-solid-900.ttf", BinaryFile(&FAsolidTTF, 604800))
	http.HandleFunc("/font/fa-solid-900.woff", BinaryFile(&FAsolidWOFF, 604800))

	http.HandleFunc("/font/materialicons.eot", BinaryFile(&materialIconsEot, 604800))
	http.HandleFunc("/font/materialicons.ttf", BinaryFile(&materialIconsTtf, 604800))
	http.HandleFunc("/font/materialicons.woff", BinaryFile(&materialIconsWoff, 604800))

	return nil
}

var firsts map[string]bool

func FirstRequestOnSite(site string, am AccessManager) {
	if firsts == nil {
		firsts = make(map[string]bool)
	}
	if _, found := firsts[site]; found {
		return
	}
	firsts[site] = true
	am.Log().Debug("First access to site %s since appserver start", site)

	val := am.Setting().Get(site, "self.signup")
	if val == nil {
		am.Setting().Put(site, "self.signup", "no")
	}
	val = am.Setting().Get(site, "session.expiry")
	if val == nil {
		am.Setting().Put(site, "session.expiry", "900")
	}
	val = am.Setting().Get(site, "smtp.hostname")
	if val == nil {
		am.Setting().Put(site, "smtp.hostname", "smtp.example.com")
	}
	val = am.Setting().Get(site, "smtp.port")
	if val == nil {
		am.Setting().Put(site, "smtp.port", "587")
	}
	val = am.Setting().Get(site, "support_team.name")
	if val == nil {
		am.Setting().Put(site, "support_team.name", "Unknown")
	}
	val = am.Setting().Get(site, "support_team.email")
	if val == nil {
		am.Setting().Put(site, "support_team.email", "support@example.com")
	}
}

// Serve the contents of a binary file back to the web browser
func BinaryFile(data *[]byte, cacheTime int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d,s-maxage=%d,no-transform,public", cacheTime, cacheTime/10))
		path := strings.ToLower(r.URL.Path[1:])
		if strings.HasSuffix(path, ".svg") {
			w.Header().Set("Content-type", "image/svg+xml")
		} else if strings.HasSuffix(path, ".jpg") {
			w.Header().Set("Content-type", "image/jpg")
		} else if strings.HasSuffix(path, ".css") {
			w.Header().Set("Content-type", "text/css")
		} else {
			w.Header().Set("Content-type", "application/octent-stream")
		}
		w.Header().Set("Content-length", fmt.Sprintf("%d", len(*data)))
		w.Write(*data)
	}
}

// Respond to a HTTP request using a template, and data to insert into that template
func Render(r *http.Request, w http.ResponseWriter, t *template.Template, template string, i interface{}) error {
	// w.Header().Add("Strict-Transport-Security", "max-age=3600")
	w.Header().Set("Cache-Control", "max-age=0,no-cache,no-store")
	w.Header().Add("X-Frame-Options", "deny")
	err := t.ExecuteTemplate(w, template, i)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("Error displaying %s page: %v", template, err)))
		return err
	}
	return nil
}

// Respond to a HTTP request with a HTTP redirect message
func RedirectHandler(target string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}

// Display an error page. It is expected no content has yet been sent to the browser, and no content will be sent after
func ShowError(w http.ResponseWriter, r *http.Request, t *template.Template, err error, siteName string) {
	w.WriteHeader(http.StatusInternalServerError)
	type Page struct {
		SiteName        string
		SiteDescription string
		Title           []string
		Slug            string
		Error           error
		Today           string
	}
	err = t.ExecuteTemplate(w, "error", &Page{
		siteName,
		"",
		[]string{"System error"},
		"",
		err,
		""})
	if err != nil {
		fmt.Printf("Error occurred while executing ShowError(). We wanted to show this error: %v\n", err)
		panic(fmt.Sprintf("Error displaying error page: %v", err))
	}
}

func ShowErrorNotFound(w http.ResponseWriter, r *http.Request, t *template.Template, siteName string) {
	w.WriteHeader(http.StatusNotFound)
	type Page struct {
		SiteName        string
		SiteDescription string
		Title           []string
		Slug            string
		Error           string
		Today           string
	}
	err := t.ExecuteTemplate(w, "error_not_found", &Page{
		siteName,
		"",
		[]string{"Not found"},
		"",
		"Sorry, We could not find what you are looking for",
		""})
	if err != nil {
		panic(fmt.Sprintf("Error displaying error page: %v", err))
	}
}

func DecodeOrPanic(data string) []byte {
	bin, berr := base64.StdEncoding.DecodeString(data)
	if berr != nil {
		panic(fmt.Sprintf("Error during base64 decoding of binary data in security package. %v", berr))
	}
	return bin
}

func AddSafeHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Strict-Transport-Security", "max-age=2592000; includeSubDomains")
}

func HostFromRequest(r *http.Request) string {
	host := r.Host

	if strings.Index(host, ":") > 0 {
		host = host[0:strings.Index(host, ":")]
	}

	if host == "" {
		return "localhost"
	}

	return host
}

// Extract user IP address from the http request header. Trust proxy or load balancer header information when connection is behind local network device such as proxy or load balancer.
func IpFromRequest(r *http.Request) string {
	ip := r.RemoteAddr

	if strings.HasPrefix(ip, "[") {
		p := strings.Split(ip, "]")
		ip = p[0][1:]
	} else if strings.Contains(ip, ":") {
		p := strings.Split(ip, ":")
		ip = p[0]
	}

	// Trust proxy/forwarded information if the source IP is a local ip address.
	// This fails in some cases, such as if the web server and load balancer or
	// reverse proxy use public IP addresses.

	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "0:0:0:0") || strings.HasPrefix(ip, "169.254.") {
		var providedIp string
		if len(r.Header.Get("HTTP_X_FORWARDED_FOR")) > 0 {
			providedIp = r.Header.Get("HTTP_X_FORWARDED_FOR")
		}
		if len(r.Header.Get("X-Forwarded-For")) > 0 {
			providedIp = r.Header.Get("X-Forwarded-For")
		}

		if len(providedIp) > 0 {
			i := strings.Index(providedIp, ",")
			if i > 0 {
				providedIp = providedIp[0 : i-1]
			}
			return strings.TrimSpace(providedIp)
		}

	}

	return ip
}

// Inspect the cookie and IP address of a request and return associated session information
func LookupSession(r *http.Request, am AccessManager) (Session, error) {
	cookie, err := r.Cookie("z")
	if err != nil {
		if err == http.ErrNoCookie {
			err = nil
		}
		return am.GuestSession(HostFromRequest(r)), err
	}
	token := ""
	if cookie != nil && cookie.Value != "" {
		token = cookie.Value
	}
	return am.Session(HostFromRequest(r), token)
}

// Rudimentary checks on email address
func CheckEmail(email string) string {
	if len(email) < 5 {
		return "Email address too short"
	}
	if len(email) > 400 {
		return "Email address too long"
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "Email address should contain @ symbol."
	}
	if len(parts[1]) < 3 {
		return "Email domain too short."
	}
	return ""
}

var SecurityHeader = `
{{define "security_header"}}
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<meta charset="utf-8">
		<meta property="og:site_name" content="{{.SiteName}}"/>
		<meta name="apple-mobile-web-app-title" content="{{.SiteName}}">
		<meta name="apple-mobile-web-app-capable" content="yes">
		<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=1.0, minimum-scale=1.0, maximum-scale=1.0, viewport-fit=cover">
		<title>Signin &mdash; {{.SiteName}}</title>
		<style type="text/css">
			@font-face {
				font-family: 'FontAwesomeSolid';
				src: url('/font/fa-solid-900.eot');
				src: url('/font/fa-solid-900.eot?#iefix')
				format('embedded-opentype'), url('/font/fa-solid-900.woff')
				format('woff'), url('/font/fa-solid-900.ttf') format('truetype');
				font-weight: normal;
				font-style: normal
			}

			body {
				background: #fafafa;
				background-repeat: no-repeat;
				background-position: center;
				-webkit-background-size: cover;
				-moz-background-size: cover;
				-o-background-size: cover;
				background-size: cover;
				margin-left: auto;
				margin-right: auto;
				max-width: 24em;
			}

			#signin_box h2 {
				font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
				text-align: center;
				margin-top: 0em;
				margin-bottom: 0.6em;
				color: white;
			}
			#signin_box h3,
			#signup_box h3 {
				font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
				margin-top: 0;
				margin-bottom: 1.5em;
				color: white;
				text-align: center;
				font-weight: 200;
				letter-spacing: 0.02em;
			}
			#signin_box p,
			#signup_box p {
				text-align: left;
				margin-bottom: 1.5em;
				font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
				color: white;
				font-size: 1em;
				color: #ddd;
				margin-top: 1.2em;
			}
			#signin_box,
			#signup_box {
				margin-bottom: 1.5em;
				padding: 1em 2.5em 1em 2.5em;
				border: 1px solid #e6e6e6;
				background: #fff;
			}
			form {
				padding: 0;
				margin: 0;
			}
			body > div#signin_box {
				margin-top: 2em;
			}
			body > div#signin_box,
			body > div#signup_box {
				border: 0px;
				max-width: 20em;
				background-color: rgba(30,30,30,0.85);
				border-radius: 0.5em;
				margin-bottom: 1.5em;
				padding: 1.5em 2.0em 1.5em 2.0em;
			}

			#signin_box input[type=text], #signup_box input[type=text],
			#signin_box input[type=email], #signup_box input[type=email],
			#signin_box input[type=password], #signup input[type=password] {
				border: 1px solid rgba(0, 0, 0, 0.23);
				border-radius: 0.5em;
				background: rgba(93, 93, 93, 0.41);
				margin-bottom: 0.4em;
				font-size: 1em;
				width: 100%;
				color: white;
				padding: 0.56em;
			}
			#signin_box p.forgot,
			#signup_box p.forgot {
				text-align: right;
				margin: 0 0 1.6em 0;
			}
			p > a {
				color: #ccc;
				font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
				font-size: 0.8em;
			}
			#signup_box input[type=submit], #signin_box input[type=submit] {
				background: #a44;
				border: 0px;
				font-size: 1em;
				padding: 0.6em;
				border-radius: 0.35em;
				-webkit-border-radius: 0.35em;
				-moz-border-radius: 0.35em;
				color: white;
				font-weight: 400;
				width: 100%;
				margin-top: 0.15em;
				-webkit-appearance: none;
				-moz-appearance: none;
		}
		#signup_box input[type=submit]:hover,
		#signin_box input[type=submit]:hover {
			background: #933;
		}

		div.feedback {
			padding: 0.4em 1em 0.4em 0.7em;
			margin: 1em 0em 1em 0em;
			clear: both;
			background: #b9deff;
			border-radius: 0.6em;
			border: 1px solid #a9ceef;
			font-family: "Helvetica Neue", Helvetica, sans-serif;
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


{{.SupplimentalCss | safe}}
	</style>
</head>
<body class="signin">
{{end}}


{{define "security_footer"}}
</body></html>
{{end}}
`

var ErrorTemplates = `
{{define "error"}}
<html>
	<head>
		<title>Sorry. a problem occurred</title>
		<style type="text/css">
body, h1, h2, h3, div, p { font-family: Helvetica Neue, Helvetica, Arial, Sans-sersif }
body { margin-left: auto; margin-right: auto; max-width: 40em; margin-top: 5%; }
.button {
	display: inline-block;
	outline: none;
	cursor: pointer;
	text-align: center;
	text-decoration: none;
	font: 14px/100% Arial, Helvetica, sans-serif;
	padding: .5em 2em .55em;
	text-shadow: 0 1px 1px rgba(0,0,0,.3);
	border-radius: .5em; -webkit-border-radius: .5em; -moz-border-radius: .5em;
	box-shadow: 0 1px 2px rgba(0,0,0,.2); -webkit-box-shadow: 0 1px 2px rgba(0,0,0,.2); -moz-box-shadow: 0 1px 2px rgba(0,0,0,.2);
}
.button:hover {
	text-decoration: none;
}
.button:active {
	position: relative;
	top: 1px;
}

.orange {
	color: #fef4e9;
	border: solid 1px #da7c0c;
	background: #f78d1d;
	background: -webkit-gradient(linear, left top, left bottom, from(#faa51a), to(#f47a20));
	background: -moz-linear-gradient(top,  #faa51a,  #f47a20);
	filter:  progid:DXImageTransform.Microsoft.gradient(startColorstr='#faa51a', endColorstr='#f47a20');
}
.orange:hover {
	background: #f47c20;
	background: -webkit-gradient(linear, left top, left bottom, from(#f88e11), to(#f06015));
	background: -moz-linear-gradient(top,  #f88e11,  #f06015);
	filter:  progid:DXImageTransform.Microsoft.gradient(startColorstr='#f88e11', endColorstr='#f06015');
}
.orange:active {
	color: #fcd3a5;
	background: -webkit-gradient(linear, left top, left bottom, from(#f47a20), to(#faa51a));
	background: -moz-linear-gradient(top,  #f47a20,  #faa51a);
	filter:  progid:DXImageTransform.Microsoft.gradient(startColorstr='#f47a20', endColorstr='#faa51a');
}
		</style>
	</head>
<body>

<h1>Sorry, a problem occurred</h1>
<p>
A problem occured while attempting to display this page. Please try again shortly.
</p>

<div style="margin-left: 2em; margin-bottom: 1em; background: #eee; padding: 1em;"/>
<p style="margin:0;">The technical details of the problem are as follows:</p>
<pre style="margin-bottom: 0;">
{{.Error}}
</pre>
</div>

<div>
<a class="button orange"  href="/">Go back to the home page</a>
</div>

</body></html>
{{end}}



{{define "error_not_found"}}
<html>
<head>
<title>We can't find what you are looking for</title>
<style type="text/css">
* { font-family: Helvetica Neue, Helvetica, Arial, Sans-sersif }
body { margin-left: auto; margin-right: auto; max-width: 40em; margin-top: 5%; }
.button {
	display: inline-block;
	outline: none;
	cursor: pointer;
	text-align: center;
	text-decoration: none;
	font: 14px/100% Arial, Helvetica, sans-serif;
	padding: .5em 2em .55em;
	text-shadow: 0 1px 1px rgba(0,0,0,.3);
	border-radius: .5em; -webkit-border-radius: .5em; -moz-border-radius: .5em;
	box-shadow: 0 1px 2px rgba(0,0,0,.2); -webkit-box-shadow: 0 1px 2px rgba(0,0,0,.2); -moz-box-shadow: 0 1px 2px rgba(0,0,0,.2);
}
.button:hover {
	text-decoration: none;
}
.button:active {
	position: relative;
	top: 1px;
}

.orange {
	color: #fef4e9;
	border: solid 1px #da7c0c;
	background: #f78d1d;
	background: -webkit-gradient(linear, left top, left bottom, from(#faa51a), to(#f47a20));
	background: -moz-linear-gradient(top,  #faa51a,  #f47a20);
	filter:  progid:DXImageTransform.Microsoft.gradient(startColorstr='#faa51a', endColorstr='#f47a20');
}
.orange:hover {
	background: #f47c20;
	background: -webkit-gradient(linear, left top, left bottom, from(#f88e11), to(#f06015));
	background: -moz-linear-gradient(top,  #f88e11,  #f06015);
	filter:  progid:DXImageTransform.Microsoft.gradient(startColorstr='#f88e11', endColorstr='#f06015');
}
.orange:active {
	color: #fcd3a5;
	background: -webkit-gradient(linear, left top, left bottom, from(#f47a20), to(#faa51a));
	background: -moz-linear-gradient(top,  #f47a20,  #faa51a);
	filter:  progid:DXImageTransform.Microsoft.gradient(startColorstr='#f47a20', endColorstr='#faa51a');
}
</style>
</head>
<body>

<div style="text-align:center">

<h1>Oops!</h1>
<p>
We've looked everywhere, but we can't seem to find what you are looking for.
</p>


<div>
<a class="button orange"  href="/">Go back to the home page</a>
</div>

</div>

</body></html>
{{end}}
`

var AdminTemplate = `
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
