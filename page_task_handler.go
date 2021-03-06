package security

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
)

func TaskHandlerPage(t *template.Template, am AccessManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := IpFromRequest(r)

		// Pull useful headers from Task request.
		q, ok := r.Header["X-Appengine-Queuename"]
		queueName := ""
		if ok {
			queueName = q[0]
		}
		if queueName == "" {
			w.WriteHeader(202) // Accepted ok, but no action to do
			fmt.Println("warning: X-Appengine-Queuename not set" + ip + "\n")
			return
		}

		// Process an incoming task
		t, ok := r.Header["X-Appengine-Taskname"]
		if !ok || len(t[0]) == 0 {
			fmt.Printf("warning: X-Appengine-Taskname header not set" + ip + "\n")
			http.Error(w, "X-Appengine-Taskname header not set. "+ip, http.StatusBadRequest)
			return
		}
		taskId := t[0]

		// Extract the request body for further task details.
		bodyData, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("Task(%s): error reading task http body: %s\n", taskId, err)
			http.Error(w, "Failed reading request body: "+err.Error(), http.StatusInternalServerError)
			return
		}

		message := make(map[string]interface{})
		err = json.Unmarshal(bodyData, &message)
		if err != nil {
			fmt.Printf("Received task on '%s' queue. Message: %s\n", queueName, string(bodyData))
			fmt.Printf("Task(%s): Failed decoding message %v\n", taskId, err)
			http.Error(w, "Failed decoding request body: "+err.Error(), http.StatusInternalServerError)
			return
		}

		task := ""
		site := ""
		if _, ok = message["site"]; ok {
			site = message["site"].(string)
		}
		if _, ok = message["type"]; ok {
			task = message["type"].(string)
		}
		fmt.Printf("Received task '%s' on '%s' queue for host '%s'.\n", task, queueName, site)
		fmt.Printf("   Message: %s\n", string(bodyData))

		if site == "" {
			w.WriteHeader(202) // Accepted ok, but cant do anything
			fmt.Printf("unknown site\n")
			return
		}

		session := am.GuestSession(site, ip, "", "")
		b := am.GetSyslogBundle(session.Site())
		defer b.Put()

		if task == "" {
			fmt.Printf("unknown task type\n")
			w.WriteHeader(202) // Accepted ok, but cant do anything
			b.Add(queueName, session.IP(), "warn", ``, fmt.Sprintf("Task(%s): Unknown task type: %s", taskId, queueName))
			return
		}

		// Log and output details of the task.
		b.Add(queueName, "", "debug", ``, fmt.Sprintf("Received task '%s' on '%s' queue for host '%s'. %s\n", task, queueName, site, string(bodyData)))

		found, err := am.RunTaskHandler(task, session, message)

		if !found {
			w.WriteHeader(202) // Accepted ok, but cant do anything
			b.Add(queueName, session.IP(), "warn", ``, fmt.Sprintf("Task(%s): Unhandled task type: %s", taskId, queueName))
			fmt.Println("    Task unhandled from queue:", queueName)
			return
		}
		if err != nil {
			msg := fmt.Sprintf("Failed executing task %s: %v", queueName, err)
			b.Add("connector", session.IP(), ``, "error", msg)
			http.Error(w, msg, http.StatusInternalServerError)
		}

	}
}
