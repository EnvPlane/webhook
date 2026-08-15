package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/envpilot/webhook/internal/scm"
)

func TestGitHubWebhookValidatesSignatureAndSubmitsNormalizedJob(t *testing.T) {
	var submissions atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		submissions.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/jobs" {
			http.Error(w, "unexpected control-plane request", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer control-plane-token" {
			http.Error(w, "unexpected authorization", http.StatusUnauthorized)
			return
		}
		var event scm.PullRequestEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "decode normalized event: "+err.Error(), http.StatusBadRequest)
			return
		}
		if event.Provider != scm.ProviderGitHub || event.Action != scm.ActionOpen || event.Repo != "owner/repo" || event.ChangeID != "42" || event.EventID != "delivery-42" {
			http.Error(w, "unexpected normalized event", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"job-42","status":"queued"}`)
	}))
	defer controlPlane.Close()

	application := newTestServer(t, controlPlane.URL)
	body := []byte(`{"action":"opened","number":42,"pull_request":{"number":42,"html_url":"https://github.com/owner/repo/pull/42","draft":false,"head":{"ref":"feature/42","sha":"abc42"},"user":{"login":"octocat"},"labels":[]},"repository":{"full_name":"owner/repo"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "delivery-42")
	req.Header.Set("X-Hub-Signature-256", githubSignature("github-secret", body))
	rec := httptest.NewRecorder()
	application.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || submissions.Load() != 1 {
		t.Fatalf("webhook response=%d body=%s submissions=%d", rec.Code, rec.Body.String(), submissions.Load())
	}
}

func TestGitHubWebhookRejectsInvalidSignatureWithoutSubmission(t *testing.T) {
	var submissions atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		submissions.Add(1)
	}))
	defer controlPlane.Close()
	application := newTestServer(t, controlPlane.URL)
	body := []byte(`{"action":"opened"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", "sha256=invalid")
	rec := httptest.NewRecorder()
	application.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized || submissions.Load() != 0 {
		t.Fatalf("response=%d submissions=%d", rec.Code, submissions.Load())
	}
	metrics := httptest.NewRecorder()
	application.Routes().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `outcome="invalid_signature"`) {
		t.Fatalf("metrics do not contain invalid signature outcome: %s", metrics.Body.String())
	}
	ready := httptest.NewRecorder()
	application.Routes().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before successful forward = %d", ready.Code)
	}
}

func TestGitHubIssueCommentWebhookSubmitsCommand(t *testing.T) {
	var command scm.PullRequestCommand
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/jobs/commands" {
			http.Error(w, "unexpected control-plane path", http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&command); err != nil {
			http.Error(w, "decode command: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"job-command-1"}`)
	}))
	defer controlPlane.Close()
	application := newTestServer(t, controlPlane.URL)
	body := []byte(`{"action":"created","issue":{"number":42,"html_url":"https://github.com/owner/repo/issues/42","pull_request":{"url":"https://api.github.com/repos/owner/repo/pulls/42"}},"comment":{"body":"/envpilot destroy","user":{"login":"octocat"}},"repository":{"full_name":"owner/repo"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "issue_comment")
	req.Header.Set("X-GitHub-Delivery", "comment-42")
	req.Header.Set("X-Hub-Signature-256", githubSignature("github-secret", body))
	rec := httptest.NewRecorder()
	application.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || command.Command != scm.CommandDestroy || command.ChangeID != "42" || command.EventID != "comment-42" {
		t.Fatalf("response=%d command=%#v body=%s", rec.Code, command, rec.Body.String())
	}
}

func TestGitLabWebhookValidatesTokenAndSubmitsMergeRequest(t *testing.T) {
	var received scm.PullRequestEvent
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "decode event: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"job-7"}`)
	}))
	defer controlPlane.Close()
	application := newTestServer(t, controlPlane.URL)
	body := []byte(`{"object_kind":"merge_request","user":{"username":"alice"},"project":{"id":9,"path_with_namespace":"group/repo"},"object_attributes":{"iid":7,"action":"open","state":"opened","source_branch":"feature/7","url":"https://gitlab.example/group/repo/-/merge_requests/7","last_commit":{"id":"def7"}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/gitlab", bytes.NewReader(body))
	req.Header.Set("X-Gitlab-Event", "Merge Request Hook")
	req.Header.Set("X-Gitlab-Token", "gitlab-token")
	req.Header.Set("X-Gitlab-Event-UUID", "gitlab-delivery-7")
	rec := httptest.NewRecorder()
	application.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || received.Provider != scm.ProviderGitLab || received.ChangeID != "7" || received.EventID != "gitlab-delivery-7" {
		t.Fatalf("response=%d event=%#v body=%s", rec.Code, received, rec.Body.String())
	}
}

func TestConfigRequiresControlPlaneCredentialsAndProviderSecret(t *testing.T) {
	tests := []Config{
		{Addr: ":8080", ControlPlaneToken: "token", GitHubWebhookSecret: "secret", RequestTimeout: time.Second},
		{Addr: ":8080", ControlPlaneURL: "https://api.example", GitHubWebhookSecret: "secret", RequestTimeout: time.Second},
		{Addr: ":8080", ControlPlaneURL: "https://api.example", ControlPlaneToken: "token", RequestTimeout: time.Second},
	}
	for _, cfg := range tests {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected invalid config: %#v", cfg)
		}
	}
}

func newTestServer(t *testing.T, controlPlaneURL string) *Server {
	t.Helper()
	application, err := New(Config{
		Addr:                ":8080",
		ControlPlaneURL:     controlPlaneURL,
		ControlPlaneToken:   "control-plane-token",
		GitHubWebhookSecret: "github-secret",
		GitLabWebhookToken:  "gitlab-token",
		RequestTimeout:      time.Second,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func githubSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestGitLabTokenComparisonRejectsDifferentLength(t *testing.T) {
	if validGitLabToken("secret", "secret ") || validGitLabToken("secret", strings.Repeat("x", 7)) {
		t.Fatal("invalid GitLab token accepted")
	}
}
