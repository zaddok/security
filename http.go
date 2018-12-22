package security

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/mail"
	"strings"
	"time"
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

func SigninPage(t *template.Template, am AccessManager, siteName string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)

		ip := IpFromRequest(r)
		session, failure, err := am.Authenticate(HostFromRequest(r), r.FormValue("signin_email"), r.FormValue("signin_password"), ip)
		if err != nil {
			am.Log().Error("Error during authentication: %s", err)
			ShowError(w, r, t, errors.New("An error occurred, please try again shortly."), siteName)

			//http.Redirect(w, r, "/?e=f", http.StatusTemporaryRedirect)
			return
		}
		if failure != "" || session == nil {
			am.Log().Error("Error during authentication: %s %s", failure, err)
			//http.Redirect(w, r, "/?e=f", http.StatusTemporaryRedirect)
			//return

			p := &SignupPageData{}
			p.FirstName = strings.TrimSpace(r.FormValue("first_name"))
			p.LastName = strings.TrimSpace(r.FormValue("last_name"))
			p.Email = strings.TrimSpace(r.FormValue("email"))
			p.Password = strings.TrimSpace(r.FormValue("password"))
			p.Password2 = strings.TrimSpace(r.FormValue("password2"))
			if r.FormValue("r") != "" {
				p.Referer = r.FormValue("r")
			}
			//p.TermsAndConditions = len(strings.TrimSpace(r.FormValue("terms_and_conditions"))) > 0 ||
			//	len(strings.TrimSpace(r.FormValue("i_agree"))) > 0
			p.AllowSignup = !(strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no")) == "no")
			if failure != "" {
				p.Errors = append(p.Errors, failure)
			}
			p.SiteName = siteName
			p.AllowSignup = !(strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no")) == "no")

			err = t.ExecuteTemplate(w, "signin_page", p)
			if err != nil {
				am.Log().Notice("Error displaying 'signup' page: %v", err)
				w.Write([]byte("Error displaying 'signup' page"))
				return
			}
		}

		// Signin successful
		refer := ""
		if r.FormValue("referer") != "" {
			if strings.Index(r.FormValue("referer"), "/") < 0 {
				refer = r.FormValue("referer")
			}
		}

		cookie := &http.Cookie{
			Name:     "z",
			Value:    session.GetToken(),
			Path:     "/",
			Secure:   false,
			HttpOnly: true,
			Expires:  time.Now().Add(time.Minute * 60 * 24 * time.Duration(COOKIE_DAYS)),
			MaxAge:   60 * 60 * 24 * COOKIE_DAYS,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/"+refer+"?e=s", http.StatusTemporaryRedirect)
	}
}

func SignoutPage(t *template.Template, am AccessManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)
		session, err := am.Invalidate("cookie", HostFromRequest(r))
		if err != nil {
			am.Log().Notice("Error displaying 'signout' page: %v", err)
			w.Write([]byte("Error displaying 'signout' page"))
			return
		}

		// wipe cookie
		cookie := &http.Cookie{
			Name:     "z",
			Value:    session.GetToken(),
			Path:     "/",
			Expires:  time.Now().Add(time.Minute * 60 * 24 * -356),
			Secure:   false,
			HttpOnly: true,
			MaxAge:   0,
		}
		http.SetCookie(w, cookie)
		if err != nil && session != nil && session.IsAuthenticated() {
			am.Log().Info("Signout from %s %s", session.GetFirstName(), session.GetLastName())
		}
		http.Redirect(w, r, "/?e=s", http.StatusTemporaryRedirect)
	}
}

type SignupPageData struct {
	SiteName    string
	SigninEmail string
	FirstName   string
	LastName    string
	Email       string
	Password    string
	Password2   string
	Referer     string
	AllowSignup bool
	Errors      []string
	Infos       []string
	Successes   []string
}

func SignupPage(t *template.Template, am AccessManager, siteName string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)
		am.Log().Debug("Singup page")
		session, err := LookupSession(r, am)
		if err != nil {
			am.Log().Notice("Error fetching session data %s", err)
			w.Write([]byte("Error fetching session data"))
			return
		}

		if session.IsAuthenticated() {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		p := &SignupPageData{}
		p.FirstName = strings.TrimSpace(r.FormValue("first_name"))
		p.LastName = strings.TrimSpace(r.FormValue("last_name"))
		p.Email = strings.TrimSpace(r.FormValue("email"))
		p.Password = strings.TrimSpace(r.FormValue("password"))
		p.Password2 = strings.TrimSpace(r.FormValue("password2"))
		if r.FormValue("r") != "" {
			p.Referer = r.FormValue("r")
		}
		//p.TermsAndConditions = len(strings.TrimSpace(r.FormValue("terms_and_conditions"))) > 0 ||
		//	len(strings.TrimSpace(r.FormValue("i_agree"))) > 0
		p.AllowSignup = !(strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no")) == "no")

		signupRequested := len(r.FormValue("signup")) > 0 || len(r.FormValue("register_firstname")) > 0
		var signupMessage []string

		if signupRequested {
			if len(p.FirstName) < 1 {
				signupMessage = append(signupMessage, "Please specify your first name.")
			}
			if len(p.FirstName) > 100 {
				signupMessage = append(signupMessage, "First name must be less than 100 characters.")
			}
			if len(p.LastName) < 1 {
				signupMessage = append(signupMessage, "Please specify your last name.")
			}
			if len(p.LastName) > 100 {
				signupMessage = append(signupMessage, "Last name must be less than 100 characters.")
			}
			if len(p.Email) < 1 {
				signupMessage = append(signupMessage, "Please specify your email address.")
			} else {
				_, perr := mail.ParseAddress(p.Email)
				if perr != nil {
					signupMessage = append(signupMessage, "Please specify a valid email address.")
				}
			}
			if len(p.Email) > 255 {
				signupMessage = append(signupMessage, "Email address must be less than 250 characters.")
			}
			//if !p.TermsAndConditions {
			//	signupMessage = append(signupMessage, "Please confirm you agree with the terms and conditions.")
			//}
			if len(p.Password) < 1 {
				signupMessage = append(signupMessage, "Please specify your desired password.")
			} else if len(p.Password) < 6 {
				signupMessage = append(signupMessage, "Please specify a password with at least 6 characters.")
			} else if len(p.Password) > 200 {
				signupMessage = append(signupMessage, "Password must be less than 200 characters.")
			} else if len(p.Password2) < 1 {
				signupMessage = append(signupMessage, "Please re-enter your password.")
			} else if p.Password != p.Password2 {
				signupMessage = append(signupMessage, "You typed your password twice, but they do not match.")
			}
			if len(signupMessage) > 0 {
				p.Errors = signupMessage
			} else {
				ip := IpFromRequest(r)
				errors, _, err := am.Signup(HostFromRequest(r), p.FirstName, p.LastName, p.Email, p.Password, ip)
				if errors != nil {
					p.Errors = *errors
				} else if err != nil {
					p.Errors = append(p.Errors, err.Error())
				} else {
					p.Successes = append(p.Successes, "To complete your sign up, please check your email for instructions on how to verify your email address.")
					p.FirstName = ""
					p.LastName = ""
					p.Email = ""
					p.Password = ""
					p.Password2 = ""
				}
			}
		}
		p.SiteName = siteName

		err = t.ExecuteTemplate(w, "signin_page", p)
		if err != nil {
			am.Log().Notice("Error displaying 'signup' page: %v", err)
			w.Write([]byte("Error displaying 'signup' page"))
			return
		}
	}
}

func ForgotPage(t *template.Template, am AccessManager, siteName string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)
		am.Log().Debug("Forgot password page")

		_, err := LookupSession(r, am)
		if err != nil {
			am.Log().Notice("Error fetching session data %s", err)
			w.Write([]byte("Error fetching session data"))
			return
		}

		type Page struct {
			SiteName    string
			SigninEmail string
			Errors      []string
			Infos       []string
			Successes   []string
		}
		p := &Page{}
		p.SiteName = siteName

		if r.FormValue("signin_email") != "" {
			p.Infos = append(p.Infos, "If this email address is in our system, you should receive an email shortly with a password reset link.")
		}

		err = t.ExecuteTemplate(w, "forgot_password_page", p)
		if err != nil {
			am.Log().Notice("Error displaying 'forgot' page: %v", err)
			w.Write([]byte("Error displaying 'forgot' page"))
			return
		}
	}
}

func ActivatePage(t *template.Template, am AccessManager, siteName string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		p := &SignupPageData{}

		token := r.URL.Path
		if strings.HasPrefix(token, "/activate/") {
			token = token[10:]
		}
		if len(token) > 0 && token[len(token)-1] == '/' {
			token = token[0 : len(token)-1]
		}

		ip := IpFromRequest(r)
		cookie, failure, err := am.ActivateSignup(HostFromRequest(r), token, ip)

		if len(cookie) > 0 {
			/*
				// Uncomment if you wish clicking on the activate link to auto-sign in the person
				// clicking on the activation link. For security reasons, its better to require
				// the activation link and the users password.
				c := &http.Cookie{
					Name:     "z",
					Value:    cookie,
					Path:     "/",
					Secure:   false,
					HttpOnly: true,
					Expires:  time.Now().Add(time.Duration(COOKIE_DAYS) * 24 * time.Hour),
					MaxAge:   60 * 60 * 24 * COOKIE_DAYS,
				}
				http.SetCookie(w, c)
			*/
			p.Successes = append(p.Successes, "Thank you for confirming your email address. Your account is now active.")
		}
		if failure != "" {
			p.Errors = append(p.Errors, failure)
		}
		if err != nil {
			p.Errors = append(p.Errors, fmt.Sprintf("Activation problem: %s", err))
		}
		p.SiteName = siteName
		p.AllowSignup = !(strings.ToLower(am.Setting().GetWithDefault(HostFromRequest(r), "self.signup", "no")) == "no")

		err = t.ExecuteTemplate(w, "signin_page", p)
		if err != nil {
			am.Log().Notice("Error displaying 'signup' page: %v", err)
			w.Write([]byte("Error displaying 'signup' page"))
			return
		}
	}
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
