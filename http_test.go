package security

import (
	"testing"
	"time"

	"github.com/zaddok/log"
)

func TestHtmlCompiles(t *testing.T) {

	l := log.NewStdoutLogDebug()
	defer l.Close()

	am, err, client, context := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), inferLocation(t))
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	tm := NewGaeTicketManager(client, context, am)

	_, err = RegisterHttpHandlers("name", "description", "body{}", am, tm, time.Now().Location(), l)
	if err != nil {
		t.Fatalf("RegisterHttpHandlers() failed: %v", err)
	}

}
