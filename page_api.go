package security

import (
	"html/template"
	"net/http"
	"strings"
)

func ApiPage(t *template.Template, am AccessManager, siteName, siteDescription string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AddSafeHeaders(w)

		session, err := LookupSession(r, am)
		if err != nil {
			w.WriteHeader(501)
			w.Write([]byte(`{"error":"Internal Error", "error_details":"`))
			w.Write([]byte(err.Error()))
			w.Write([]byte(`"}`))
			return
		}

		if !session.IsAuthenticated() {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"Not Authenticated"}`))
			return
		}

		path := r.URL.Path[1:]
		parts := strings.Split(path, "/")
		command := parts[len(parts)-1]

		if command == "watch" {
			w.WriteHeader(404)
			w.Write([]byte(`{"status":true}`))
			return
		}

		w.WriteHeader(404)
		w.Write([]byte(`{"error":"Not found"}`))
		return
	}
}
