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
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/envplane/webhook/internal/scm"
)

const (
	maxWebhookBody          = 2 << 20
	defaultReplayTTL        = 15 * time.Minute
	maxRememberedDeliveries = 4096
	defaultRatePerSecond    = 30.0
	defaultRateBurst        = 60
)

type Config struct {
	Addr              string
	ControlPlaneURL   string
	ControlPlaneToken string
	// ReceiverToken is a capability token accepted solely by the control-plane
	// webhook receiver endpoint. ControlPlaneToken remains for legacy commands.
	ReceiverToken              string
	GitHubWebhookSecret        string
	GitLabTokenResolver        func(context.Context, string, string) (string, error)
	GitLabMemberAccessResolver func(context.Context, string, string) (int, error)
	GitLabAPIURL               string
	GitLabAPIToken             string
	RequestTimeout             time.Duration
	ReadyStaleAfter            time.Duration
	ReplayTTL                  time.Duration
	RateLimitPerSecond         float64
	RateLimitBurst             int
	ControlPlaneRetries        int
	RetryBackoff               time.Duration
}

func ConfigFromEnv() Config {
	var gitLabResolver func(context.Context, string, string) (string, error)
	if strings.EqualFold(strings.TrimSpace(os.Getenv("ENVPLANE_WEBHOOK_LEGACY_LOCAL_GITLAB_VERIFICATION")), "true") {
		gitLabResolver = gitLabTokenResolverFromEnv()
	}
	requestTimeout := durationFromEnv("ENVPLANE_WEBHOOK_REQUEST_TIMEOUT", 10*time.Second)
	controlPlaneRetries := intFromEnv("ENVPLANE_WEBHOOK_CONTROL_PLANE_RETRIES", 3)
	retryBackoff := durationFromEnv("ENVPLANE_WEBHOOK_RETRY_BACKOFF", 100*time.Millisecond)
	return Config{
		Addr:                       envOrDefault("ENVPLANE_WEBHOOK_ADDR", ":8080"),
		ControlPlaneURL:            strings.TrimRight(strings.TrimSpace(os.Getenv("ENVPLANE_CONTROL_PLANE_URL")), "/"),
		ControlPlaneToken:          strings.TrimSpace(os.Getenv("ENVPLANE_CONTROL_PLANE_TOKEN")),
		ReceiverToken:              strings.TrimSpace(os.Getenv("ENVPLANE_WEBHOOK_RECEIVER_TOKEN")),
		GitHubWebhookSecret:        strings.TrimSpace(os.Getenv("ENVPLANE_GITHUB_WEBHOOK_SECRET")),
		GitLabTokenResolver:        gitLabResolver,
		GitLabMemberAccessResolver: gitLabMemberAccessResolverFromEnv(requestTimeout, controlPlaneRetries, retryBackoff),
		GitLabAPIURL:               envOrDefault("ENVPLANE_GITLAB_API_URL", "https://gitlab.com/api/v4"),
		GitLabAPIToken:             strings.TrimSpace(os.Getenv("ENVPLANE_GITLAB_API_TOKEN")),
		RequestTimeout:             requestTimeout,
		ReadyStaleAfter:            durationFromEnv("ENVPLANE_WEBHOOK_READY_STALE_AFTER", 2*time.Minute),
		ReplayTTL:                  durationFromEnv("ENVPLANE_WEBHOOK_REPLAY_TTL", defaultReplayTTL),
		RateLimitPerSecond:         floatFromEnv("ENVPLANE_WEBHOOK_RATE_LIMIT_RPS", defaultRatePerSecond),
		RateLimitBurst:             intFromEnv("ENVPLANE_WEBHOOK_RATE_LIMIT_BURST", defaultRateBurst),
		ControlPlaneRetries:        controlPlaneRetries,
		RetryBackoff:               retryBackoff,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func gitLabMemberAccessResolverFromEnv(timeout time.Duration, retries int, backoff time.Duration) func(context.Context, string, string) (int, error) {
	token := strings.TrimSpace(os.Getenv("ENVPLANE_GITLAB_API_TOKEN"))
	if token == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if retries <= 0 {
		retries = 1
	}
	baseURL := strings.TrimRight(envOrDefault("ENVPLANE_GITLAB_API_URL", "https://gitlab.com/api/v4"), "/")
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context, projectID, userID string) (int, error) {
		if strings.TrimSpace(projectID) == "" || strings.TrimSpace(userID) == "" {
			return 0, errors.New("GitLab project and user IDs are required for membership lookup")
		}
		endpoint := baseURL + "/projects/" + url.PathEscape(projectID) + "/members/all/" + url.PathEscape(userID)
		for attempt := 0; attempt < retries; attempt++ {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				return 0, err
			}
			req.Header.Set("PRIVATE-TOKEN", token)
			response, err := client.Do(req)
			if err == nil {
				if response.StatusCode == http.StatusNotFound {
					_ = response.Body.Close()
					return 0, nil
				}
				if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
					var member struct {
						AccessLevel int `json:"access_level"`
					}
					decodeErr := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&member)
					_ = response.Body.Close()
					if decodeErr != nil {
						return 0, fmt.Errorf("decode GitLab membership response: %w", decodeErr)
					}
					return member.AccessLevel, nil
				}
				err = fmt.Errorf("GitLab membership lookup returned HTTP %d", response.StatusCode)
			}
			if response != nil {
				_ = response.Body.Close()
			}
			retryable := response == nil || retryableGitLabStatus(responseStatus(response))
			if attempt+1 == retries || !retryable {
				return 0, err
			}
			if err := waitForRetry(ctx, backoff, attempt); err != nil {
				return 0, err
			}
		}
		return 0, errors.New("GitLab membership lookup retry loop exhausted")
	}
}

func responseStatus(response *http.Response) int {
	if response == nil {
		return 0
	}
	return response.StatusCode
}

func retryableGitLabStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func gitLabTokenResolverFromEnv() func(context.Context, string, string) (string, error) {
	raw := strings.TrimSpace(os.Getenv("ENVPLANE_GITLAB_WEBHOOK_TOKENS"))
	if raw == "" {
		return nil
	}
	var tokens map[string]string
	if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
		return func(context.Context, string, string) (string, error) {
			return "", fmt.Errorf("parse ENVPLANE_GITLAB_WEBHOOK_TOKENS: %w", err)
		}
	}
	return func(_ context.Context, projectID, projectPath string) (string, error) {
		if token := strings.TrimSpace(tokens[projectID]); token != "" {
			return token, nil
		}
		if token := strings.TrimSpace(tokens[projectPath]); token != "" {
			return token, nil
		}
		return "", errors.New("GitLab project token is not configured")
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Addr) == "" {
		return fmt.Errorf("webhook address is required")
	}
	if strings.TrimSpace(c.ControlPlaneURL) == "" {
		return fmt.Errorf("ENVPLANE_CONTROL_PLANE_URL is required")
	}
	if !strings.HasPrefix(c.ControlPlaneURL, "http://") && !strings.HasPrefix(c.ControlPlaneURL, "https://") {
		return fmt.Errorf("ENVPLANE_CONTROL_PLANE_URL must be an HTTP(S) URL")
	}
	if strings.TrimSpace(c.ReceiverToken) == "" {
		return fmt.Errorf("ENVPLANE_WEBHOOK_RECEIVER_TOKEN is required")
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("webhook request timeout must be positive")
	}
	if c.ReadyStaleAfter <= 0 {
		return fmt.Errorf("webhook readiness stale threshold must be positive")
	}
	if c.ReplayTTL <= 0 {
		return fmt.Errorf("webhook replay TTL must be positive")
	}
	if c.RateLimitPerSecond <= 0 {
		return fmt.Errorf("webhook rate limit must be positive")
	}
	if c.RateLimitBurst <= 0 {
		return fmt.Errorf("webhook rate limit burst must be positive")
	}
	if c.ControlPlaneRetries <= 0 {
		return fmt.Errorf("control-plane retry count must be positive")
	}
	if c.RetryBackoff < 0 {
		return fmt.Errorf("webhook retry backoff must not be negative")
	}
	return nil
}

type Server struct {
	cfg                     Config
	client                  *http.Client
	logger                  *slog.Logger
	metricsMu               sync.Mutex
	deliveries              map[string]uint64
	forwardCount            uint64
	forwardSeconds          float64
	lastControlPlaneSuccess int64
	replayMu                sync.Mutex
	recentDeliveries        map[string]time.Time
	limiter                 *rateLimiter
}

func New(cfg Config, client *http.Client, logger *slog.Logger) (*Server, error) {
	if cfg.ReadyStaleAfter == 0 {
		cfg.ReadyStaleAfter = 2 * time.Minute
	}
	if cfg.ReplayTTL == 0 {
		cfg.ReplayTTL = defaultReplayTTL
	}
	if cfg.RateLimitPerSecond == 0 {
		cfg.RateLimitPerSecond = defaultRatePerSecond
	}
	if cfg.RateLimitBurst == 0 {
		cfg.RateLimitBurst = defaultRateBurst
	}
	if cfg.ControlPlaneRetries == 0 {
		cfg.ControlPlaneRetries = 3
	}
	if cfg.RetryBackoff == 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.RequestTimeout}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, client: client, logger: logger, deliveries: map[string]uint64{}, recentDeliveries: map[string]time.Time{}, limiter: newRateLimiter(cfg.RateLimitPerSecond, cfg.RateLimitBurst)}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /livez", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.Handle("POST /api/v1/webhooks/github", s.rateLimit(http.HandlerFunc(s.githubWebhook)))
	mux.Handle("POST /webhook/github", s.rateLimit(http.HandlerFunc(s.githubWebhook)))
	mux.Handle("POST /api/v1/webhooks/gitlab", s.rateLimit(http.HandlerFunc(s.gitlabWebhook)))
	return mux
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow(clientIP(r)) {
			s.recordDelivery("webhook", "rate_limited")
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, errors.New("webhook rate limit exceeded"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

type rateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]rateBucket
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{rate: rate, burst: float64(burst), buckets: make(map[string]rateBucket)}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxRememberedDeliveries {
			var oldestKey string
			var oldest time.Time
			for candidate, candidateBucket := range l.buckets {
				if oldestKey == "" || candidateBucket.last.Before(oldest) {
					oldestKey, oldest = candidate, candidateBucket.last
				}
			}
			delete(l.buckets, oldestKey)
		}
		bucket = rateBucket{tokens: l.burst, last: now}
	}
	bucket.tokens = minFloat(l.burst, bucket.tokens+now.Sub(bucket.last).Seconds()*l.rate)
	bucket.last = now
	if bucket.tokens < 1 {
		l.buckets[key] = bucket
		return false
	}
	bucket.tokens--
	l.buckets[key] = bucket
	return true
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("X-EnvPlane-Webhook-Receiver", "v1")
	lastSuccess := atomic.LoadInt64(&s.lastControlPlaneSuccess)
	last := time.Unix(0, lastSuccess)
	if lastSuccess == 0 || time.Since(last) > s.cfg.ReadyStaleAfter {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) recordDelivery(provider, outcome string) {
	s.metricsMu.Lock()
	s.deliveries[provider+"|"+outcome]++
	s.metricsMu.Unlock()
}

func (s *Server) recordForward(provider string, started time.Time) {
	s.metricsMu.Lock()
	s.forwardCount++
	s.forwardSeconds += time.Since(started).Seconds()
	s.deliveries[provider+"|accepted"]++
	s.metricsMu.Unlock()
	atomic.StoreInt64(&s.lastControlPlaneSuccess, time.Now().UnixNano())
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintln(w, "# HELP webhook_deliveries_total Webhook deliveries by provider and outcome")
	_, _ = fmt.Fprintln(w, "# TYPE webhook_deliveries_total counter")
	for key, count := range s.deliveries {
		parts := strings.SplitN(key, "|", 2)
		_, _ = fmt.Fprintf(w, "webhook_deliveries_total{provider=%q,outcome=%q} %d\n", parts[0], parts[1], count)
	}
	_, _ = fmt.Fprintln(w, "# HELP webhook_forward_duration_seconds Total duration of successful control-plane forwards")
	_, _ = fmt.Fprintln(w, "# TYPE webhook_forward_duration_seconds summary")
	_, _ = fmt.Fprintf(w, "webhook_forward_duration_seconds_count %d\nwebhook_forward_duration_seconds_sum %.6f\n", s.forwardCount, s.forwardSeconds)
}

func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	provider := string(scm.ProviderGitHub)
	body, err := readBody(w, r)
	if err != nil {
		s.recordDelivery(provider, "body_error")
		s.logRejection(r, provider, "body_error", "")
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !validGitHubSignature(s.cfg.GitHubWebhookSecret, r.Header.Get("X-Hub-Signature-256"), body) {
		s.recordDelivery(provider, "invalid_signature")
		s.logRejection(r, provider, "invalid_signature", "")
		writeError(w, http.StatusUnauthorized, errors.New("invalid webhook signature"))
		return
	}
	eventType := strings.TrimSpace(r.Header.Get("X-GitHub-Event"))
	if eventType == "issue_comment" {
		command, err := scm.ParseGitHubPRCommand(body)
		if err != nil {
			s.recordDelivery(provider, "parse_error")
			writeError(w, http.StatusBadRequest, err)
			return
		}
		command.EventID = strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
		if command.Command == "" {
			s.recordDelivery(provider, "ignored_event")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
			return
		}
		if err := validateCommand(command); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := authorizeCommand(command); err != nil {
			s.recordDelivery(provider, "unauthorized_author")
			s.logRejection(r, provider, "unauthorized_author", "issue_comment")
			writeError(w, http.StatusForbidden, err)
			return
		}
		if s.rejectReplay(w, r, provider, command.EventID) {
			return
		}
		s.submitCommand(w, r, command)
		return
	}
	if eventType != "pull_request" {
		s.recordDelivery(provider, "ignored_event")
		s.logger.Info("unsupported GitHub webhook event", "event", eventType)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	event, err := scm.ParseGitHubPullRequest(body)
	if err != nil {
		s.recordDelivery(provider, "parse_error")
		writeError(w, http.StatusBadRequest, err)
		return
	}
	event.EventID = strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	if event.Action == scm.ActionIgnore {
		s.recordDelivery(provider, "ignored_event")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	if s.rejectReplay(w, r, provider, event.EventID) {
		return
	}
	s.submit(w, r, event)
}

func (s *Server) gitlabWebhook(w http.ResponseWriter, r *http.Request) {
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
		if strings.TrimSpace(s.cfg.ReceiverToken) == "" {
			writeError(w, http.StatusServiceUnavailable, errors.New("webhook receiver token is not configured"))
			return
		}
		command.EventID = strings.TrimSpace(r.Header.Get("X-Gitlab-Event-UUID"))
		if command.EventID == "" {
			command.EventID = command.PullRequestEvent(scm.ActionUpdate).DeduplicationKey()
		}
		if command.Command == "" {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
			return
		}
		if err := validateCommand(command); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if s.cfg.GitLabMemberAccessResolver == nil {
			s.recordDelivery(string(scm.ProviderGitLab), "author_membership_unavailable")
			writeError(w, http.StatusServiceUnavailable, errors.New("GitLab author membership lookup is not configured"))
			return
		}
		accessLevel, lookupErr := s.cfg.GitLabMemberAccessResolver(r.Context(), command.InstallationID, command.AuthorID)
		if lookupErr != nil {
			s.recordDelivery(string(scm.ProviderGitLab), "author_membership_lookup_failed")
			s.logger.Warn("GitLab author membership lookup failed", "project_id", command.InstallationID, "user_id", command.AuthorID, "error", lookupErr)
			writeError(w, http.StatusServiceUnavailable, errors.New("GitLab author membership is unavailable"))
			return
		}
		command.AuthorAccessLevel = accessLevel
		if err := authorizeCommand(command); err != nil {
			s.recordDelivery(string(scm.ProviderGitLab), "unauthorized_author")
			s.logRejection(r, string(scm.ProviderGitLab), "unauthorized_author", "Note Hook")
			writeError(w, http.StatusForbidden, err)
			return
		}
		s.submitGitLabRawCommand(w, r, body, command)
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
		event.EventID = event.DeduplicationKey()
	}
	if strings.TrimSpace(s.cfg.ReceiverToken) != "" {
		s.submitGitLabRaw(w, r, body, event)
		return
	}
	writeError(w, http.StatusServiceUnavailable, errors.New("webhook receiver token is not configured"))
}

func (s *Server) submitGitLabRaw(w http.ResponseWriter, r *http.Request, body []byte, event scm.PullRequestEvent) {
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	response, err := s.doControlPlaneRequest(ctx, s.cfg.ControlPlaneURL+"/api/v1/webhook-receiver/gitlab", body, map[string]string{
		"Authorization":             "Bearer " + s.cfg.ReceiverToken,
		"Content-Type":              "application/json",
		"X-Gitlab-Token":            r.Header.Get("X-Gitlab-Token"),
		"X-Gitlab-Event-UUID":       r.Header.Get("X-Gitlab-Event-UUID"),
		"X-Gitlab-Event":            r.Header.Get("X-Gitlab-Event"),
		"X-Gitlab-Project-ID":       event.InstallationID,
		"X-EnvPlane-Webhook-Probe":  r.Header.Get("X-EnvPlane-Webhook-Probe"),
		"X-EnvPlane-Delivery-Nonce": r.Header.Get("X-EnvPlane-Delivery-Nonce"),
		"Idempotency-Key":           strings.TrimSpace(event.EventID),
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, errors.New("control-plane is unavailable"))
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		writeError(w, response.StatusCode, errors.New("GitLab delivery was rejected"))
		return
	}
	s.recordForward(string(scm.ProviderGitLab), time.Now())
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

func (s *Server) submitGitLabRawCommand(w http.ResponseWriter, r *http.Request, body []byte, command scm.PullRequestCommand) {
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	response, err := s.doControlPlaneRequest(ctx, s.cfg.ControlPlaneURL+"/api/v1/webhook-receiver/gitlab-command", body, map[string]string{
		"Authorization":                  "Bearer " + s.cfg.ReceiverToken,
		"Content-Type":                   "application/json",
		"X-Gitlab-Token":                 r.Header.Get("X-Gitlab-Token"),
		"X-Gitlab-Event-UUID":            r.Header.Get("X-Gitlab-Event-UUID"),
		"X-Gitlab-Event":                 r.Header.Get("X-Gitlab-Event"),
		"X-Gitlab-Project-ID":            command.InstallationID,
		"X-EnvPlane-Webhook-Probe":       r.Header.Get("X-EnvPlane-Webhook-Probe"),
		"X-EnvPlane-Delivery-Nonce":      r.Header.Get("X-EnvPlane-Delivery-Nonce"),
		"X-EnvPlane-Author-Access-Level": strconv.Itoa(command.AuthorAccessLevel),
		"Idempotency-Key":                strings.TrimSpace(command.EventID),
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, errors.New("control-plane is unavailable"))
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		writeError(w, response.StatusCode, errors.New("GitLab command was rejected"))
		return
	}
	s.recordForward(string(scm.ProviderGitLab), time.Now())
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// The replay cache is process-local. Multi-replica deployments need sticky routing
// or a shared idempotency store in front of this service for cluster-wide protection.
func (s *Server) rejectReplay(w http.ResponseWriter, r *http.Request, provider, deliveryID string) bool {
	deliveryID = strings.TrimSpace(deliveryID)
	if deliveryID == "" {
		s.recordDelivery(provider, "missing_delivery_id")
		s.logRejection(r, provider, "missing_delivery_id", r.Header.Get("X-GitHub-Event"))
		writeError(w, http.StatusBadRequest, errors.New("webhook delivery id is required"))
		return true
	}
	key := provider + "|" + deliveryID
	now := time.Now()
	s.replayMu.Lock()
	for rememberedKey, seenAt := range s.recentDeliveries {
		if now.Sub(seenAt) >= s.cfg.ReplayTTL {
			delete(s.recentDeliveries, rememberedKey)
		}
	}
	if _, exists := s.recentDeliveries[key]; exists {
		s.replayMu.Unlock()
		s.recordDelivery(provider, "duplicate_ignored")
		s.logRejection(r, provider, "duplicate_delivery", r.Header.Get("X-GitHub-Event"))
		writeJSON(w, http.StatusOK, map[string]string{"status": "duplicate_ignored"})
		return true
	}
	if len(s.recentDeliveries) >= maxRememberedDeliveries {
		var oldestKey string
		var oldest time.Time
		for rememberedKey, seenAt := range s.recentDeliveries {
			if oldestKey == "" || seenAt.Before(oldest) {
				oldestKey, oldest = rememberedKey, seenAt
			}
		}
		delete(s.recentDeliveries, oldestKey)
	}
	s.recentDeliveries[key] = now
	s.replayMu.Unlock()
	return false
}

func (s *Server) validGitLabRequest(r *http.Request, projectID, projectPath string) bool {
	if s.cfg.GitLabTokenResolver == nil {
		return false
	}
	want, err := s.cfg.GitLabTokenResolver(r.Context(), strings.TrimSpace(projectID), strings.TrimSpace(projectPath))
	if err != nil {
		s.logger.Warn("GitLab webhook token resolution failed", "project_id", projectID, "error", err)
		return false
	}
	return validGitLabToken(want, r.Header.Get("X-Gitlab-Token"))
}

func (s *Server) rejectGitLabToken(w http.ResponseWriter, r *http.Request) {
	s.recordDelivery(string(scm.ProviderGitLab), "invalid_signature")
	s.logRejection(r, string(scm.ProviderGitLab), "invalid_signature", strings.TrimSpace(r.Header.Get("X-Gitlab-Event")))
	writeError(w, http.StatusUnauthorized, errors.New("invalid webhook token"))
}

func (s *Server) doControlPlaneRequest(ctx context.Context, endpoint string, payload []byte, headers map[string]string) (*http.Response, error) {
	for attempt := 0; attempt < s.cfg.ControlPlaneRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		response, err := s.client.Do(req)
		if err == nil && !retryableControlPlaneStatus(response.StatusCode) {
			return response, nil
		}
		if attempt+1 == s.cfg.ControlPlaneRetries {
			return response, err
		}
		if response != nil {
			_ = response.Body.Close()
		}
		if err := waitForRetry(ctx, s.cfg.RetryBackoff, attempt); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("control-plane retry loop exhausted")
}

func retryableControlPlaneStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func waitForRetry(ctx context.Context, base time.Duration, attempt int) error {
	delay := base
	for index := 0; index < attempt; index++ {
		delay *= 2
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// The control-plane jobs API must deduplicate requests by Idempotency-Key and
// return the original result for repeated keys. This protects retries after a
// response is lost between the two services.
func (s *Server) submit(w http.ResponseWriter, r *http.Request, event scm.PullRequestEvent) {
	started := time.Now()
	payload, err := json.Marshal(event)
	if err != nil {
		s.recordDelivery(string(event.Provider), "upstream_error")
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	endpoint := "/api/v1/webhook-receiver/events"
	token := strings.TrimSpace(s.cfg.ReceiverToken)
	// The fallback preserves existing manually configured receiver deployments
	// during migration. Helm-managed deployments always set ReceiverToken.
	if token == "" {
		endpoint = "/api/v1/jobs"
		token = s.cfg.ControlPlaneToken
	}
	response, err := s.doControlPlaneRequest(ctx, s.cfg.ControlPlaneURL+endpoint, payload, map[string]string{
		"Authorization":               "Bearer " + token,
		"Content-Type":                "application/json",
		"Accept":                      "application/json",
		"X-EnvPlane-Webhook-Provider": string(event.Provider),
		"Idempotency-Key":             strings.TrimSpace(event.EventID),
	})
	if err != nil {
		s.logger.Error("control-plane job submission failed", "provider", event.Provider, "event_id", event.EventID, "error", err)
		writeError(w, http.StatusBadGateway, errors.New("control-plane is unavailable"))
		return
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, errors.New("invalid control-plane response"))
		return
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		s.recordDelivery(string(event.Provider), "upstream_error")
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
	s.recordForward(string(event.Provider), started)
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

func authorizeCommand(command scm.PullRequestCommand) error {
	switch command.Provider {
	case scm.ProviderGitHub:
		switch strings.ToUpper(strings.TrimSpace(command.AuthorAssociation)) {
		case "OWNER", "MEMBER", "COLLABORATOR":
			return nil
		default:
			return errors.New("webhook command author is not authorized")
		}
	case scm.ProviderGitLab:
		if command.AuthorAccessLevel >= 30 && strings.TrimSpace(command.AuthorID) != "" {
			return nil
		}
		return errors.New("webhook command author is not authorized")
	default:
		return errors.New("webhook command provider is not authorized")
	}
}

// The control-plane commands API shares the same Idempotency-Key contract as
// the jobs API and must not create a second job for a repeated delivery.
func (s *Server) submitCommand(w http.ResponseWriter, r *http.Request, command scm.PullRequestCommand) {
	started := time.Now()
	payload, err := json.Marshal(command)
	if err != nil {
		s.recordDelivery(string(command.Provider), "upstream_error")
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	response, err := s.doControlPlaneRequest(ctx, s.cfg.ControlPlaneURL+"/api/v1/jobs/commands", payload, map[string]string{
		"Authorization":   "Bearer " + s.cfg.ControlPlaneToken,
		"Content-Type":    "application/json",
		"Idempotency-Key": strings.TrimSpace(command.EventID),
	})
	if err != nil {
		s.logger.Error("control-plane command submission failed", "provider", command.Provider, "event_id", command.EventID, "error", err)
		writeError(w, http.StatusBadGateway, errors.New("control-plane is unavailable"))
		return
	}
	defer func() { _ = response.Body.Close() }()
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
	s.recordForward(string(command.Provider), started)
	s.logger.Info("webhook command submitted", "provider", command.Provider, "event_id", command.EventID, "command", command.Command)
	jobID := strings.TrimSpace(result.JobID)
	if jobID == "" {
		jobID = strings.TrimSpace(result.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "jobId": jobID})
}

func (s *Server) logRejection(r *http.Request, provider, reason, eventType string) {
	s.logger.Warn("webhook rejected", "provider", provider, "reason", reason, "delivery_id", r.Header.Get("X-GitHub-Delivery"), "event_type", eventType, "remote_addr", r.RemoteAddr)
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
	if want == "" {
		return false
	}
	wantDigest := sha256.Sum256([]byte(want))
	gotDigest := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(wantDigest[:], gotDigest[:]) == 1
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

func floatFromEnv(key string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func intFromEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
