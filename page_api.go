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
			internalError(w, err)
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
			// TODO: Add more security
			objectUuid := r.FormValue("uuid")
			objectType := r.FormValue("type")
			objectName := r.FormValue("name")
			if objectUuid == "" {
				invalidParameter(w, "Invalid object `uuid`")
				return
			}
			if objectType == "" {
				invalidParameter(w, "Invalid object `type`")
				return
			}
			if objectName == "" {
				invalidParameter(w, "Invalid object `name`")
				return
			}
			err := am.StartWatching(objectUuid, objectName, objectType, session)
			if err != nil {
				internalError(w, err)
				return
			}
			w.WriteHeader(200)
			w.Write([]byte(`{"status":true}`))
			return
		}

		if command == "unwatch" {
			// TODO: Add more security
			objectUuid := r.FormValue("uuid")
			objectType := r.FormValue("type")
			if objectUuid == "" {
				invalidParameter(w, "Invalid object `uuid`")
				return
			}
			if objectType == "" {
				invalidParameter(w, "Invalid object `type`")
				return
			}
			err := am.StopWatching(objectUuid, objectType, session)
			if err != nil {
				internalError(w, err)
				return
			}
			w.WriteHeader(200)
			w.Write([]byte(`{"status":true}`))
			return
		}

		w.WriteHeader(404)
		w.Write([]byte(`{"error":"Not found"}`))
		return
	}
}

func internalError(w http.ResponseWriter, err error) {
	w.WriteHeader(501)
	w.Write([]byte(`{"error":"Internal Error", "error_details":"`))
	w.Write([]byte(err.Error()))
	w.Write([]byte(`"}`))
}

func invalidParameter(w http.ResponseWriter, message string) {
	w.WriteHeader(501)
	w.Write([]byte(`{"error":"Invalid Parameter", "error_details":"`))
	w.Write([]byte(message))
	w.Write([]byte(`"}`))
}
