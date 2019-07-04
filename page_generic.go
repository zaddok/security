package security

import (
	"html/template"
	"net/http"
	"strings"
	"time"
)

// Serve a generic html page that does not need any variables inserted into it
func GenericPage(t *template.Template, name string, title string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=6,s-maxage=6,no-transform,public")

		if strings.HasSuffix(name, "_xml") {
			w.Header().Set("Content-type", "text/xml; charset=utf-8")
			w.Write([]byte("<?xml version=\"1.0\"?>"))
		}

		year := time.Now().Year()
		type Page struct {
			Title []string
			Slug  string
			Year  int
		}

		headerTitle := []string{}
		if len(title) > 0 {
			headerTitle = []string{title}
		}

		Render(r, w, t, name, &Page{
			headerTitle,
			time.Now().Format("2006/01/02/"),
			year})
	}
}
