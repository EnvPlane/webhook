package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/envpilot/webhook/internal/scm"
)

const maxWebhookBody = 2 << 20

type Config struct {
	Addr                string
	ControlPlaneURL     string
	ControlPlaneToken   string
	GitHubWebhookSecret string
	GitLabWebhookToken  string
	RequestTimeout      time.Duration
}

func ConfigFromEnv() Config {
	return Config{
		Addr:                envOrDefault("ENVPILOT_WEBHOOK_ADDR", ":8080"),
		ControlPlaneURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("ENVPILOT_CONTROL_PLANE_URL")), "/"),
		ControlPlaneToken:   strings.TrimSpace(os.Getenv("ENVPILOT_CONTROL_PLANE_TOKEN")),
		GitHubWebhookSecret: strings.TrimSpace(os.Getenv("ENVPILOT_GITHUB_WEBHOOK_SECRET")),
		GitLabWebhookToken:  strings.TrimSpace(os.Getenv("ENVPILOT_GITLAB_WEBHOOK_TOKEN")),
		RequestTimeout:      durationFromEnv("ENVPILOT_WEBHOOK_REQUEST_TIMEOUT", 10*time.Second),
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Addr) == "" {
		return fmt.Errorf("webhook address is required")
	}
	if strings.TrimSpace(c.ControlPlaneURL) == "" {
		return fmt.Errorf("ENVPILOT_CONTROL_PLANE_URL is required")
	}
	if !strings.HasPrefix(c.ControlPlaneURL, "http://") && !strings.HasPrefix(c.ControlPlaneURL, "https://") {
		return fmt.Errorf("ENVPILOT_CONTROL_PLANE_URL must be an HTTP(S) URL")
	}
	if strings.TrimSpace(c.ControlPlaneToken) == "" {
		return fmt.Errorf("ENVPILOT_CONTROL_PLANE_TOKEN is required")
	}
	if strings.TrimSpace(c.GitHubWebhookSecret) == "" && strings.TrimSpace(c.GitLabWebhookToken) == "" {
		return fmt.Errorf("configure at least one webhook provider secret")
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("webhook request timeout must be positive")
	}
	return nil
}

type Server struct {
	cfg    Config
	client *http.Client
	logger *slog.Logger
}

func New(cfg Config, client *http.Client, logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.RequestTimeout}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, client: client, logger: logger}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /livez", s.health)
	mux.HandleFunc("POST /api/v1/webhooks/github", s.githubWebhook)
	mux.HandleFunc("POST /webhook/github", s.githubWebhook)
	mux.HandleFunc("POST /api/v1/webhooks/gitlab", s.gitlabWebhook)
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !validGitHubSignature(s.cfg.GitHubWebhookSecret, r.Header.Get("X-Hub-Signature-256"), body) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid webhook signature"))
		return
	}
	eventType := strings.TrimSpace(r.Header.Get("X-GitHub-Event"))
	if eventType == "issue_comment" {
		command, err := scm.ParseGitHubPRCommand(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		command.EventID = strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
		if command.Command == "" {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
			return
		}
		if err := validateCommand(command); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.submitCommand(w, r, command)
		return
	}
	if eventType != "pull_request" {
		s.logger.Info("unsupported GitHub webhook event", "event", eventType)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	event, err := scm.ParseGitHubPullRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	event.EventID = strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	if event.Action == scm.ActionIgnore {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	s.submit(w, r, event)
}

func (s *Server) gitlabWebhook(w http.ResponseWriter, r *http.Request) {
	if !validGitLabToken(s.cfg.GitLabWebhookToken, r.Header.Get("X-Gitlab-Token")) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid webhook token"))
		return
	}
	eventType := strings.TrimSpace(r.Header.Get("X-Gitlab-Event"))
	if eventType == "Note Hook" {
		body, err := readBody(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		command, err := scm.ParseGitLabPRCommand(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		command.EventID = strings.TrimSpace(r.Header.Get("X-Gitlab-Event-UUID"))
		if command.EventID == "" {
			command.EventID = strings.TrimSpace(r.Header.Get("X-Gitlab-Delivery"))
		}
		if command.Command == "" {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
			return
		}
		if err := validateCommand(command); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.submitCommand(w, r, command)
		return
	}
	if eventType != "" && eventType != "Merge Request Hook" {
		s.logger.Info("unsupported GitLab webhook event", "event", eventType)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	event, err := scm.ParseGitLabMergeRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	event.EventID = strings.TrimSpace(r.Header.Get("X-Gitlab-Event-UUID"))
	if event.EventID == "" {
		event.EventID = strings.TrimSpace(r.Header.Get("X-Gitlab-Delivery"))
	}
	if event.Action == scm.ActionIgnore {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	if err := validateEvent(event); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.submit(w, r, event)
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request, event scm.PullRequestEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.ControlPlaneURL+"/api/v1/jobs", bytes.NewReader(payload))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.ControlPlaneToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-EnvPlane-Webhook-Provider", string(event.Provider))
	response, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("control-plane job submission failed", "provider", event.Provider, "event_id", event.EventID, "error", err)
		writeError(w, http.StatusBadGateway, errors.New("control-plane is unavailable"))
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, errors.New("invalid control-plane response"))
		return
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		s.logger.Error("control-plane rejected webhook job", "provider", event.Provider, "event_id", event.EventID, "status", response.StatusCode)
		writeError(w, http.StatusBadGateway, fmt.Errorf("control-plane rejected job with HTTP %d", response.StatusCode))
		return
	}
	var job struct {
		ID string `json:"id"`
	}
	if len(bytes.TrimSpace(responseBody)) > 0 && json.Unmarshal(responseBody, &job) != nil {
		writeError(w, http.StatusBadGateway, errors.New("invalid control-plane response"))
		return
	}
	s.logger.Info("webhook job submitted", "provider", event.Provider, "event_id", event.EventID, "repository", event.Repo, "change_id", event.ChangeID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "jobId": job.ID})
}

func validateEvent(event scm.PullRequestEvent) error {
	if strings.TrimSpace(event.Repo) == "" || strings.TrimSpace(event.ChangeID) == "" {
		return errors.New("webhook event repository and change id are required")
	}
	return nil
}

func validateCommand(command scm.PullRequestCommand) error {
	if strings.TrimSpace(command.Repo) == "" || strings.TrimSpace(command.ChangeID) == "" {
		return errors.New("webhook command repository and change id are required")
	}
	return nil
}

func (s *Server) submitCommand(w http.ResponseWriter, r *http.Request, command scm.PullRequestCommand) {
	payload, err := json.Marshal(command)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.ControlPlaneURL+"/api/v1/jobs/commands", bytes.NewReader(payload))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.ControlPlaneToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("control-plane command submission failed", "provider", command.Provider, "event_id", command.EventID, "error", err)
		writeError(w, http.StatusBadGateway, errors.New("control-plane is unavailable"))
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		writeError(w, http.StatusBadGateway, fmt.Errorf("control-plane rejected command with HTTP %d", response.StatusCode))
		return
	}
	var result struct {
		ID     string `json:"id"`
		JobID  string `json:"jobId"`
		Status string `json:"status"`
	}
	if len(bytes.TrimSpace(responseBody)) > 0 && json.Unmarshal(responseBody, &result) != nil {
		writeError(w, http.StatusBadGateway, errors.New("invalid control-plane response"))
		return
	}
	s.logger.Info("webhook command submitted", "provider", command.Provider, "event_id", command.EventID, "command", command.Command)
	jobID := strings.TrimSpace(result.JobID)
	if jobID == "" {
		jobID = strings.TrimSpace(result.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "jobId": jobID})
}

func validGitHubSignature(secret, signature string, body []byte) bool {
	secret = strings.TrimSpace(secret)
	signature = strings.TrimSpace(signature)
	if secret == "" || !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

func validGitLabToken(want, got string) bool {
	want = strings.TrimSpace(want)
	if want == "" || len(want) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		return nil, fmt.Errorf("read webhook body: %w", err)
	}
	return body, nil
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationFromEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return duration
}
