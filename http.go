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
		w.Header().Set("Content-type", "application/octent-stream")
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
