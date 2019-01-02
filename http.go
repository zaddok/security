package security

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

var COOKIE_DAYS = 365

func RegisterHttpHandlers() {

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

		div.error, div.info, div.success, div.warning {
			padding: 0.4em 1em 0.3em 0.7em;
			margin-bottom: 1em;
			clear: both;
		}
		div.info { border: 1px solid #bbe; background: #ddf; color: #558; }
		div.success { border: 1px solid #aFcA80; color: #4F8A10; background-color: #DFF2BF; }
		div.warning { border: 1px solid #e4e4c8; color: #aa2; background-color: #ffffd0; }
		div.error { border: 1px solid #C99; background: #FCC; color: #633; }
		div.info::before, div.success::before, div.warning::before, div.error::before {
			font-family: FontAwesomeSolid;
			opacity: 0.45;
			float: left;
		}
		div.error::before { content: "\f057\00a0\00a0"; opacity: 0.45; color: #933; }
		div.info:before { content: "\f05a\00a0\00a0"; opacity: 0.4; color: #339; }
		div.success::before { content: "\f00c\00a0\00a0"; opacity: 0.7; color: #4F8A10; }
		div.warning::before { content: "\f071\00a0\00a0"; opacity: 0.5; color: #aa2; }
		div.error ul,
		div.warning ul { padding: 0 0 0 2em; margin: 0; }
		div.error p,
		div.success p,
		div.warning p,
		div.info p { padding: 0 0 0 1.6em; margin: 0; }
		div.error ul li,
		div.success ul li,
		div.warning ul li,
		div.info ul li { padding: 0; margin: 0; list-style-type: none; }
{{.SupplimentalCss | safe}}
	</style>
</head>
<body class="signin">
{{end}}


{{define "security_footer"}}
</body></html>
{{end}}
`
