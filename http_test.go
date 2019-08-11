package security

import (
	"testing"
	"time"

	"github.com/zaddok/log"
)

func TestHtmlCompiles(t *testing.T) {

	l := log.NewStdoutLogDebug()
	defer l.Close()

	am, err, client, context := NewGaeAccessManager(projectId, inferLocation(t), time.Now().Location())
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}
	tm := NewGaeTicketManager(client, context, am)

	_, err = RegisterHttpHandlers(am, tm, time.Now().Location(), l)
	if err != nil {
		t.Fatalf("RegisterHttpHandlers() failed: %v", err)
	}

}
