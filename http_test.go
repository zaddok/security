package security

import (
	"testing"
	"time"

	"github.com/zaddok/log"
)

func TestHtmlCompiles(t *testing.T) {

	l := log.NewStdoutLogDebug()
	defer l.Close()

	am, err, _, _ := NewGaeAccessManager(requireEnv("GOOGLE_CLOUD_PROJECT", t), l)
	if err != nil {
		t.Fatalf("NewGaeAccessManager() failed: %v", err)
	}

	_, err = RegisterHttpHandlers("name", "description", "body{}", am, time.Now().Location(), l)
	if err != nil {
		t.Fatalf("RegisterHttpHandlers() failed: %v", err)
	}

}
