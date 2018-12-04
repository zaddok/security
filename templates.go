package security

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// Serve the contents of a binary file back to the web browser
func BinaryFile(data []byte, cacheTime int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d,s-maxage=%d,no-transform,public", cacheTime, cacheTime/10))
		w.Header().Set("Content-type", "application/octent-stream")
		w.Header().Set("Content-length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
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

// Serve a generic html page that does not need any variables inserted into it
func GenericPage(t *template.Template, name string, title string, siteName, siteDescription string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=6,s-maxage=6,no-transform,public")

		if strings.HasSuffix(name, "_xml") {
			w.Header().Set("Content-type", "text/xml; charset=utf-8")
			w.Write([]byte("<?xml version=\"1.0\"?>"))
		}

		year := time.Now().Year()
		type Page struct {
			SiteName        string
			SiteDescription string
			Title           []string
			Slug            string
			Year            int
		}

		headerTitle := []string{}
		if len(title) > 0 {
			headerTitle = []string{title}
		}

		Render(r, w, t, name, &Page{
			siteName,
			siteDescription,
			headerTitle,
			time.Now().Format("2006/01/02/"),
			year})
	}
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
