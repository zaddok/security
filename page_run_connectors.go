package security

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

var lastConnectorCheck time.Time

func RunConnectorsPage(t *template.Template, am AccessManager, defaultTimezone *time.Location) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().In(defaultTimezone)

		if lastConnectorCheck.Unix()+65 > now.Unix() && r.FormValue("go") == "" {
			w.Write([]byte("Sleeping. Try again shortly."))
			return
		}

		for _, virtualHost := range am.AvailableSites() {
			// We will run the connectors for each virtual host in the datastore
			session, err := am.GetSystemSession(virtualHost, "Connector Scheduler", "Task")
			if err != nil {
				http.Error(w, "Datastore access failed. ", http.StatusServiceUnavailable)
				return
			}

			scheduled, err := am.GetScheduledConnectors(session)
			if err != nil {
				http.Error(w, "Datastore access failed. ", http.StatusBadRequest)
				return
			}

			for _, s := range scheduled {
				if s.Disabled == true {
					w.Write([]byte(fmt.Sprintf(" - %s %s %s %s %v (disabled)\n", virtualHost, s.Uuid, s.Label, s.Frequency, s.LastRun)))
					continue
				}
				if s.LastRun != nil && s.LastRun.Unix()+60*5 > now.Unix() {
					// Skip when last run was less than 5 minutes ago
					w.Write([]byte(fmt.Sprintf(" - %s %s %s %s %v (sleeping)\n", virtualHost, s.Uuid, s.Label, s.Frequency, s.LastRun)))
					continue
				}

				if s.Frequency == "hourly" {
					if s.LastRun == nil || s.LastRun.In(defaultTimezone).Hour() != now.Hour() {
						// Connector has never run, or was run in a different hour of the day
						w.Write([]byte(fmt.Sprintf(" - %s %s %s %s %v (run_now)\n", virtualHost, s.Uuid, s.Label, s.Frequency, s.LastRun)))
						if session.Site() == "localhost" || strings.HasPrefix(session.Site(), "dev") {
							am.Notice(session, `connector`, "Cannot run connectors in development environment as a task.")
							found := am.GetConnectorInfoByLabel(s.Label)
							err := found.Run(am, s, session)
							if err != nil {
								w.Write([]byte("Unhandled error: " + err.Error() + "\n"))

							}
						} else {
							_, err := am.CreateTask("connector", s.Uuid)
							if err == nil {
								s.LastRun = &now
								err = am.UpdateScheduledConnector(s, session)
								if err != nil {
									w.Write([]byte("Unhandled error: " + err.Error() + "\n"))

								}
							} else {
								w.Write([]byte("Unhandled error: " + err.Error() + "\n"))
							}
						}
						continue
					}
				}
				if s.Frequency == "daily" {
					if now.Hour() == s.Hour {
						if s.LastRun == nil || s.LastRun.In(defaultTimezone).Day() != now.Day() {
							// Connector has never run, we are on the correct hour of the day, and it
							// has not yet run today.
							w.Write([]byte(fmt.Sprintf(" - %s %s %s %s %v (run_now)\n", virtualHost, s.Uuid, s.Label, s.Frequency, s.LastRun)))
							if session.Site() == "localhost" || strings.HasPrefix(session.Site(), "dev") {
								am.Notice(session, `connector`, "Cannot run connectors in development environment.")
							} else {
								_, err := am.CreateTask("connector", s.Uuid)
								if err == nil {
									s.LastRun = &now
									err = am.UpdateScheduledConnector(s, session)
									if err != nil {
										w.Write([]byte("AAARGH!!!! " + err.Error() + "\n"))

									}
								} else {
									w.Write([]byte("AAARGH!!!! " + err.Error() + "\n"))
								}
							}
							continue
						}
					}
				}
				// Connector was already run recently, or it is not the right time to run it.
				w.Write([]byte(fmt.Sprintf(" - %s %s %s %v (not time)\n", s.Uuid, s.Label, s.Frequency, s.LastRun)))
			}
		}

		lastConnectorCheck = now
		w.Write([]byte("OK"))
	}
}
