package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/envplane/webhook/internal/scm"
)

func TestGitHubWebhookValidatesSignatureAndSubmitsNormalizedJob(t *testing.T) {
	var submissions atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		submissions.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/webhook-receiver/events" {
			http.Error(w, "unexpected control-plane request", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer receiver-token" {
			http.Error(w, "unexpected authorization", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Idempotency-Key"); got != "delivery-42" {
			http.Error(w, "unexpected idempotency key", http.StatusBadRequest)
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
	duplicate := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(body))
	duplicate.Header.Set("X-GitHub-Event", "pull_request")
	duplicate.Header.Set("X-GitHub-Delivery", "delivery-42")
	duplicate.Header.Set("X-Hub-Signature-256", githubSignature("github-secret", body))
	duplicateRec := httptest.NewRecorder()
	application.Routes().ServeHTTP(duplicateRec, duplicate)
	if duplicateRec.Code != http.StatusOK || submissions.Load() != 1 || !strings.Contains(duplicateRec.Body.String(), "duplicate_ignored") {
		t.Fatalf("duplicate response=%d body=%s submissions=%d", duplicateRec.Code, duplicateRec.Body.String(), submissions.Load())
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

func TestWebhookRateLimitRejectsExcessRequests(t *testing.T) {
	var submissions atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		submissions.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"job"}`)
	}))
	defer controlPlane.Close()
	application, err := New(Config{
		Addr:                ":8080",
		ControlPlaneURL:     controlPlane.URL,
		ControlPlaneToken:   "control-plane-token",
		ReceiverToken:       "receiver-token",
		GitHubWebhookSecret: "github-secret",
		RequestTimeout:      time.Second,
		ReadyStaleAfter:     time.Second,
		ReplayTTL:           time.Minute,
		RateLimitPerSecond:  0.01,
		RateLimitBurst:      2,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"opened","number":42,"pull_request":{"number":42,"html_url":"https://github.com/owner/repo/pull/42","draft":false,"head":{"ref":"feature/42","sha":"abc42"},"user":{"login":"octocat"},"labels":[]},"repository":{"full_name":"owner/repo"}}`)
	for index := 0; index < 3; index++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "pull_request")
		req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("rate-limit-%d", index))
		req.Header.Set("X-Hub-Signature-256", githubSignature("github-secret", body))
		rec := httptest.NewRecorder()
		application.Routes().ServeHTTP(rec, req)
		want := http.StatusOK
		if index == 2 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("request %d response=%d body=%s", index, rec.Code, rec.Body.String())
		}
	}
	if submissions.Load() != 2 {
		t.Fatalf("control-plane submissions=%d, want 2", submissions.Load())
	}
}

func TestWebhookRetriesTemporaryControlPlaneFailure(t *testing.T) {
	var attempts atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if got := r.Header.Get("Idempotency-Key"); got != "retry-delivery" {
			http.Error(w, "unexpected idempotency key", http.StatusBadRequest)
			return
		}
		if attempts.Load() == 1 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"job-retried"}`)
	}))
	defer controlPlane.Close()
	application, err := New(Config{
		Addr:                ":8080",
		ControlPlaneURL:     controlPlane.URL,
		ControlPlaneToken:   "control-plane-token",
		ReceiverToken:       "receiver-token",
		GitHubWebhookSecret: "github-secret",
		RequestTimeout:      time.Second,
		ReadyStaleAfter:     time.Second,
		ReplayTTL:           time.Minute,
		RateLimitPerSecond:  100,
		RateLimitBurst:      10,
		ControlPlaneRetries: 3,
		RetryBackoff:        time.Millisecond,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"opened","number":42,"pull_request":{"number":42,"html_url":"https://github.com/owner/repo/pull/42","draft":false,"head":{"ref":"feature/42","sha":"abc42"},"user":{"login":"octocat"},"labels":[]},"repository":{"full_name":"owner/repo"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "retry-delivery")
	req.Header.Set("X-Hub-Signature-256", githubSignature("github-secret", body))
	rec := httptest.NewRecorder()
	application.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || attempts.Load() != 2 || !strings.Contains(rec.Body.String(), "accepted") {
		t.Fatalf("response=%d attempts=%d body=%s", rec.Code, attempts.Load(), rec.Body.String())
	}
}

func TestGitHubIssueCommentWebhookSubmitsCommand(t *testing.T) {
	var command scm.PullRequestCommand
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/jobs/commands" {
			http.Error(w, "unexpected control-plane path", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Idempotency-Key"); got != "comment-42" {
			http.Error(w, "unexpected idempotency key", http.StatusBadRequest)
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
	body := []byte(`{"action":"created","issue":{"number":42,"html_url":"https://github.com/owner/repo/issues/42","pull_request":{"url":"https://api.github.com/repos/owner/repo/pulls/42"}},"comment":{"body":"/envplane destroy","author_association":"MEMBER","user":{"login":"octocat"}},"repository":{"full_name":"owner/repo"}}`)
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
	var externalProbeForwarded atomic.Bool
	expectedKey := "gitlab-delivery-7"
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/webhook-receiver/gitlab" || r.Header.Get("Authorization") != "Bearer receiver-token" {
			http.Error(w, "unexpected receiver request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Gitlab-Event-UUID") == "" {
			http.Error(w, "delivery id is required", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Idempotency-Key"); got != expectedKey {
			http.Error(w, "unexpected idempotency key", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-EnvPlane-Webhook-Probe") == "true" && (r.Header.Get("X-Gitlab-Project-ID") != "9" || r.Header.Get("X-Gitlab-Event") != "Merge Request Hook" || r.Header.Get("X-EnvPlane-Delivery-Nonce") != "probe-7") {
			http.Error(w, "missing webhook correlation headers", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Gitlab-Event-UUID") == "external-probe" && r.Header.Get("X-EnvPlane-Webhook-Probe") == "true" {
			externalProbeForwarded.Store(true)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read event: "+err.Error(), http.StatusBadRequest)
			return
		}
		parsed, err := scm.ParseGitLabMergeRequest(body)
		if err != nil {
			http.Error(w, "decode event: "+err.Error(), http.StatusBadRequest)
			return
		}
		received = parsed
		received.EventID = r.Header.Get("X-Gitlab-Event-UUID")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"job-7"}`)
	}))
	defer controlPlane.Close()
	application := newTestServer(t, controlPlane.URL)
	body := []byte(`{"object_kind":"merge_request","user":{"id":77,"username":"alice","access_level":30},"project":{"id":9,"path_with_namespace":"group/repo"},"object_attributes":{"iid":7,"action":"open","state":"opened","source_branch":"feature/7","url":"https://gitlab.example/group/repo/-/merge_requests/7","last_commit":{"id":"def7"}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/gitlab", bytes.NewReader(body))
	req.Header.Set("X-Gitlab-Event", "Merge Request Hook")
	req.Header.Set("X-Gitlab-Token", "gitlab-token")
	req.Header.Set("X-Gitlab-Event-UUID", "gitlab-delivery-7")
	req.Header.Set("X-EnvPlane-Webhook-Probe", "true")
	req.Header.Set("X-EnvPlane-Delivery-Nonce", "probe-7")
	req.Header.Set("X-EnvPlane-Probe-Authorization", "receiver-token")
	rec := httptest.NewRecorder()
	application.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || received.Provider != scm.ProviderGitLab || received.ChangeID != "7" || received.EventID != "gitlab-delivery-7" {
		t.Fatalf("response=%d event=%#v body=%s", rec.Code, received, rec.Body.String())
	}
	external := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/gitlab", bytes.NewReader(body))
	external.Header.Set("X-Gitlab-Event", "Merge Request Hook")
	external.Header.Set("X-Gitlab-Token", "gitlab-token")
	external.Header.Set("X-Gitlab-Event-UUID", "external-probe")
	external.Header.Set("X-EnvPlane-Webhook-Probe", "true")
	external.Header.Set("X-EnvPlane-Delivery-Nonce", "attacker-nonce")
	external.Header.Set("X-EnvPlane-Probe-Authorization", "wrong")
	expectedKey = "external-probe"
	externalRec := httptest.NewRecorder()
	application.Routes().ServeHTTP(externalRec, external)
	if externalRec.Code != http.StatusOK || externalProbeForwarded.Load() {
		t.Fatalf("external probe forwarding=%v status=%d body=%s", externalProbeForwarded.Load(), externalRec.Code, externalRec.Body.String())
	}
	legacy := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/gitlab", bytes.NewReader(body))
	legacy.Header.Set("X-Gitlab-Event", "Merge Request Hook")
	legacy.Header.Set("X-Gitlab-Token", "gitlab-token")
	legacyRec := httptest.NewRecorder()
	application.Routes().ServeHTTP(legacyRec, legacy)
	if legacyRec.Code != http.StatusBadRequest {
		t.Fatalf("legacy response=%d event_id=%q body=%s", legacyRec.Code, received.EventID, legacyRec.Body.String())
	}
	duplicate := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/gitlab", bytes.NewReader(body))
	duplicate.Header.Set("X-Gitlab-Event", "Merge Request Hook")
	duplicate.Header.Set("X-Gitlab-Token", "gitlab-token")
	duplicate.Header.Set("X-Gitlab-Event-UUID", "gitlab-delivery-7")
	expectedKey = "gitlab-delivery-7"
	duplicateRec := httptest.NewRecorder()
	application.Routes().ServeHTTP(duplicateRec, duplicate)
	if duplicateRec.Code != http.StatusOK || !strings.Contains(duplicateRec.Body.String(), "accepted") {
		t.Fatalf("duplicate response=%d body=%s", duplicateRec.Code, duplicateRec.Body.String())
	}
}

func TestGitLabNoteHookForwardsRawWithoutMembershipLookup(t *testing.T) {
	var submissions atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		submissions.Add(1)
		if r.URL.Path != "/api/v1/webhook-receiver/gitlab-command" || r.Header.Get("Authorization") != "Bearer receiver-token" {
			http.Error(w, "unexpected command receiver request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Gitlab-Token") != "gitlab-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Gitlab-Token") != "gitlab-token" || r.Header.Get("X-EnvPlane-Author-Access-Level") != "" {
			http.Error(w, "receiver must not trust author access headers", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"job-note"}`)
	}))
	defer controlPlane.Close()

	application, err := New(Config{
		Addr:                ":8080",
		ControlPlaneURL:     controlPlane.URL,
		ControlPlaneToken:   "control-plane-token",
		ReceiverToken:       "receiver-token",
		LegacyFallbackUntil: time.Now().UTC().Add(time.Hour),
		RequestTimeout:      time.Second,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"object_kind":"note","user":{"id":77,"name":"Alex","username":"alex"},"project":{"id":123,"path_with_namespace":"group/repo","web_url":"https://gitlab.example/group/repo"},"merge_request":{"iid":2201,"url":"https://gitlab.example/group/repo/-/merge_requests/2201"},"object_attributes":{"note":"/envplane destroy"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/gitlab", bytes.NewReader(body))
	req.Header.Set("X-Gitlab-Event", "Note Hook")
	req.Header.Set("X-Gitlab-Token", "gitlab-token")
	req.Header.Set("X-Gitlab-Event-UUID", "note-developer")
	rec := httptest.NewRecorder()
	application.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || submissions.Load() != 1 {
		t.Fatalf("response=%d submissions=%d body=%s", rec.Code, submissions.Load(), rec.Body.String())
	}

	denied := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/gitlab", bytes.NewReader(body))
	denied.Header.Set("X-Gitlab-Event", "Note Hook")
	denied.Header.Set("X-Gitlab-Token", "wrong")
	denied.Header.Set("X-Gitlab-Event-UUID", "note-reporter")
	deniedRec := httptest.NewRecorder()
	application.Routes().ServeHTTP(deniedRec, denied)
	if deniedRec.Code != http.StatusUnauthorized || submissions.Load() != 2 {
		t.Fatalf("denied response=%d submissions=%d body=%s", deniedRec.Code, submissions.Load(), deniedRec.Body.String())
	}
}

func TestGitLabWebhookRejectsTokenForAnotherProject(t *testing.T) {
	var submissions atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		submissions.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer controlPlane.Close()
	application, err := New(Config{
		Addr:                ":8080",
		ControlPlaneURL:     controlPlane.URL,
		ControlPlaneToken:   "control-plane-token",
		ReceiverToken:       "receiver-token",
		LegacyFallbackUntil: time.Now().UTC().Add(time.Hour),
		GitLabTokenResolver: func(_ context.Context, projectID, _ string) (string, error) {
			if projectID != "project-a" {
				return "", errors.New("unknown project")
			}
			return "token-a", nil
		},
		RequestTimeout: time.Second,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"object_kind":"merge_request","user":{"username":"alice"},"project":{"id":42,"path_with_namespace":"tenant-b/repo"},"object_attributes":{"iid":7,"action":"open","state":"opened","source_branch":"feature/7","last_commit":{"id":"def7"}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/gitlab", bytes.NewReader(body))
	req.Header.Set("X-Gitlab-Event", "Merge Request Hook")
	req.Header.Set("X-Gitlab-Token", "token-a")
	rec := httptest.NewRecorder()
	application.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized || submissions.Load() != 1 {
		t.Fatalf("response=%d submissions=%d body=%s", rec.Code, submissions.Load(), rec.Body.String())
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

func TestConfigRejectsGlobalGitLabToken(t *testing.T) {
	t.Setenv("ENVPLANE_GITLAB_WEBHOOK_TOKEN", "legacy-token")
	cfg := Config{
		Addr:                ":8080",
		ControlPlaneURL:     "https://api.example",
		ControlPlaneToken:   "token",
		GitHubWebhookSecret: "",
		RequestTimeout:      time.Second,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected global GitLab token configuration to be rejected")
	}
}

func TestConfigFromEnvResolvesGitLabTokenByProject(t *testing.T) {
	t.Setenv("ENVPLANE_WEBHOOK_LEGACY_LOCAL_GITLAB_VERIFICATION", "true")
	t.Setenv("ENVPLANE_GITLAB_WEBHOOK_TOKENS", `{"42":"token-42","group/repo":"token-path"}`)
	t.Setenv("ENVPLANE_GITLAB_WEBHOOK_TOKEN", "")
	cfg := ConfigFromEnv()
	token, err := cfg.GitLabTokenResolver(context.Background(), "42", "group/repo")
	if err != nil || token != "token-42" {
		t.Fatalf("resolved token=%q err=%v", token, err)
	}
	if _, err := cfg.GitLabTokenResolver(context.Background(), "99", "other/repo"); err == nil {
		t.Fatal("expected unknown project token lookup to fail")
	}
}

func TestConfigRejectsExpiredLegacyFallback(t *testing.T) {
	cfg := Config{
		Addr: ":8080", ControlPlaneURL: "https://api.example", ControlPlaneToken: "legacy",
		LegacyFallbackUntil: time.Now().UTC().Add(-time.Minute), RequestTimeout: time.Second,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected expired legacy fallback to be rejected")
	}
}

func TestConfigAllowsExplicitLegacyFallbackBeforeDeadline(t *testing.T) {
	cfg := Config{
		Addr: ":8080", ControlPlaneURL: "https://api.example", ControlPlaneToken: "legacy",
		LegacyFallbackUntil: time.Now().UTC().Add(time.Minute), RequestTimeout: time.Second,
		ReadyStaleAfter: time.Minute, ReplayTTL: time.Minute, RateLimitPerSecond: 1,
		RateLimitBurst: 1, ControlPlaneRetries: 1,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected explicit compatibility fallback to be accepted: %v", err)
	}
}

func TestNewWarnsWhenLegacyFallbackIsActive(t *testing.T) {
	var logs bytes.Buffer
	_, err := New(Config{
		Addr: ":8080", ControlPlaneURL: "https://api.example", ControlPlaneToken: "legacy",
		LegacyFallbackUntil: time.Now().UTC().Add(48 * time.Hour), RequestTimeout: time.Second,
		ReadyStaleAfter: time.Minute, ReplayTTL: time.Minute, RateLimitPerSecond: 1,
		RateLimitBurst: 1, ControlPlaneRetries: 1,
	}, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if got := logs.String(); !strings.Contains(got, "legacy webhook fallback is enabled") || !strings.Contains(got, "days_remaining=2") || !strings.Contains(got, "EP-WHR-007") {
		t.Fatalf("missing legacy fallback startup warning: %s", got)
	}
}

func TestLegacyFallbackRecordsDeliveryMetric(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/jobs" || r.Header.Get("Authorization") != "Bearer legacy" {
			http.Error(w, "unexpected legacy request", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer controlPlane.Close()
	application, err := New(Config{
		Addr: ":8080", ControlPlaneURL: controlPlane.URL, ControlPlaneToken: "legacy",
		LegacyFallbackUntil: time.Now().UTC().Add(time.Hour), RequestTimeout: time.Second,
		ReadyStaleAfter: time.Minute, ReplayTTL: time.Minute, RateLimitPerSecond: 1,
		RateLimitBurst: 1, ControlPlaneRetries: 1,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	recorder := httptest.NewRecorder()
	application.submit(recorder, request, scm.PullRequestEvent{Provider: scm.ProviderGitLab, EventID: "legacy-1"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("legacy submission status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	metrics := httptest.NewRecorder()
	application.Routes().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `provider="gitlab",outcome="legacy_fallback"`) {
		t.Fatalf("metrics do not contain legacy fallback outcome: %s", metrics.Body.String())
	}
}

func TestConfigFromEnvReadsLegacyFallbackDeadline(t *testing.T) {
	t.Setenv("ENVPLANE_WEBHOOK_LEGACY_FALLBACK_UNTIL", "2099-01-01T00:00:00Z")
	cfg := ConfigFromEnv()
	if cfg.LegacyFallbackUntil.IsZero() || cfg.LegacyFallbackUntil.Year() != 2099 {
		t.Fatalf("unexpected legacy fallback deadline: %v", cfg.LegacyFallbackUntil)
	}
}

func TestConfigFromEnvPrefersCanonicalValuesOverEnvPilotMigrationAliases(t *testing.T) {
	t.Setenv("ENVPLANE_CONTROL_PLANE_URL", "https://canonical.example/")
	t.Setenv("ENVPILOT_CONTROL_PLANE_URL", "https://legacy.example")
	t.Setenv("ENVPLANE_CONTROL_PLANE_TOKEN", "canonical-token")
	t.Setenv("ENVPILOT_CONTROL_PLANE_TOKEN", "legacy-token")
	t.Setenv("ENVPLANE_GITHUB_WEBHOOK_SECRET", "canonical-secret")
	t.Setenv("ENVPILOT_GITHUB_WEBHOOK_SECRET", "legacy-secret")

	cfg := ConfigFromEnv()
	if cfg.ControlPlaneURL != "https://canonical.example" {
		t.Fatalf("control plane URL = %q, want canonical value", cfg.ControlPlaneURL)
	}
	if cfg.ControlPlaneToken != "canonical-token" {
		t.Fatalf("control plane token = %q, want canonical value", cfg.ControlPlaneToken)
	}
	if cfg.GitHubWebhookSecret != "canonical-secret" {
		t.Fatalf("GitHub secret = %q, want canonical value", cfg.GitHubWebhookSecret)
	}
}

func TestConfigFromEnvSupportsEnvPilotMigrationAliases(t *testing.T) {
	t.Setenv("ENVPILOT_CONTROL_PLANE_URL", "https://legacy.example/")
	t.Setenv("ENVPILOT_CONTROL_PLANE_TOKEN", "legacy-token")
	t.Setenv("ENVPILOT_GITHUB_WEBHOOK_SECRET", "legacy-secret")

	cfg := ConfigFromEnv()
	if cfg.ControlPlaneURL != "https://legacy.example" || cfg.ControlPlaneToken != "legacy-token" || cfg.GitHubWebhookSecret != "legacy-secret" {
		t.Fatalf("migration aliases were not applied: %#v", cfg)
	}
}

func newTestServer(t *testing.T, controlPlaneURL string) *Server {
	t.Helper()
	application, err := New(Config{
		Addr:                ":8080",
		ControlPlaneURL:     controlPlaneURL,
		ControlPlaneToken:   "control-plane-token",
		ReceiverToken:       "receiver-token",
		LegacyFallbackUntil: time.Now().UTC().Add(time.Hour),
		GitHubWebhookSecret: "github-secret",
		GitLabTokenResolver: func(_ context.Context, projectID, _ string) (string, error) {
			if projectID != "9" {
				return "", errors.New("unknown project")
			}
			return "gitlab-token", nil
		},
		RequestTimeout: time.Second,
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

func TestGitLabTokenComparisonUsesFixedLengthDigests(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want bool
	}{
		{name: "exact match", got: "secret", want: true},
		{name: "same length mismatch", got: "secrex"},
		{name: "short mismatch", got: "x"},
		{name: "long mismatch", got: strings.Repeat("x", 128)},
		{name: "empty mismatch", got: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validGitLabToken("secret", tt.got); got != tt.want {
				t.Fatalf("validGitLabToken(..., %q) = %v, want %v", tt.got, got, tt.want)
			}
		})
	}
}

func TestAuthorizeCommandRequiresTrustedAuthor(t *testing.T) {
	tests := []struct {
		name    string
		command scm.PullRequestCommand
		allowed bool
	}{
		{name: "GitHub outsider", command: scm.PullRequestCommand{Provider: scm.ProviderGitHub, Command: scm.CommandDestroy, AuthorAssociation: "NONE"}},
		{name: "GitHub member", command: scm.PullRequestCommand{Provider: scm.ProviderGitHub, Command: scm.CommandDestroy, AuthorAssociation: "MEMBER"}, allowed: true},
		{name: "GitLab reporter", command: scm.PullRequestCommand{Provider: scm.ProviderGitLab, Command: scm.CommandDestroy, AuthorID: "77", AuthorAccessLevel: 20}},
		{name: "GitLab developer", command: scm.PullRequestCommand{Provider: scm.ProviderGitLab, Command: scm.CommandDestroy, AuthorID: "77", AuthorAccessLevel: 30}, allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authorizeCommand(tt.command) == nil; got != tt.allowed {
				t.Fatalf("authorized=%v, want %v", got, tt.allowed)
			}
		})
	}
}
