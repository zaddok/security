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

		fmt.Println("Recieved task. Queue:", queueName, "Message:", string(bodyData))

		message := make(map[string]interface{})
		err = json.Unmarshal(bodyData, &message)
		if err != nil {
			fmt.Printf("Task(%s): Failed decoding message %v\n", taskId, err)
			http.Error(w, "Failed decoding request body: "+err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println("    site:", message["site"].(string))
		fmt.Println("    type:", message["type"].(string))

		session := am.GuestSession(message["site"].(string), ip, "", "")
		b := am.GetSyslogBundle(session.Site())
		defer b.Put()

		// Log and output details of the task.
		b.Add(queueName, "", "debug", fmt.Sprintf("Task(%s): Recieved task %s: %s", taskId, queueName, string(bodyData)))

		found, err := am.RunTaskHandler(message["task"].(string), session, message)

		if !found {
			w.WriteHeader(202) // Accepted ok, but cant do anything
			b.Add(queueName, session.IP(), "warn", fmt.Sprintf("Task(%s): Unhandled task type: %s", taskId, queueName))
			fmt.Println("    Task unhandled from queue:", queueName)
			return
		}
		if err != nil {
			msg := fmt.Sprintf("Failed executing task %s: %v", queueName, err)
			b.Add("connector", session.IP(), "error", msg)
			http.Error(w, msg, http.StatusInternalServerError)
		}

	}
}
