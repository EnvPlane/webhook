package main

import (
	"net/http"
	"testing"
	"time"

	webhookserver "github.com/envplane/webhook/internal/server"
)

func TestNewHTTPServerConfiguresConnectionTimeouts(t *testing.T) {
	cfg := webhookserver.Config{Addr: ":8080", RequestTimeout: 10 * time.Second}
	server := newHTTPServer(cfg, http.NewServeMux())

	if server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 15*time.Second {
		t.Fatalf("ReadTimeout = %s", server.ReadTimeout)
	}
	if server.WriteTimeout != 15*time.Second {
		t.Fatalf("WriteTimeout = %s", server.WriteTimeout)
	}
	if server.IdleTimeout != 120*time.Second {
		t.Fatalf("IdleTimeout = %s", server.IdleTimeout)
	}
}
