package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	webhookserver "github.com/envplane/webhook/internal/server"
)

const (
	readHeaderTimeout = 5 * time.Second
	timeoutGrace      = 5 * time.Second
	idleTimeout       = 120 * time.Second
)

func newHTTPServer(cfg webhookserver.Config, handler http.Handler) *http.Server {
	// Read and write timeouts cover the request body and the synchronous control-plane
	// call, with five seconds of processing headroom beyond the outbound request timeout.
	processingTimeout := cfg.RequestTimeout + timeoutGrace
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       processingTimeout,
		WriteTimeout:      processingTimeout,
		IdleTimeout:       idleTimeout,
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := webhookserver.ConfigFromEnv()
	application, err := webhookserver.New(cfg, nil, logger)
	if err != nil {
		logger.Error("invalid webhook configuration", "error", err)
		os.Exit(1)
	}

	server := newHTTPServer(cfg, application.Routes())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()

	logger.Info("envplane webhook started", "address", cfg.Addr, "control_plane_url", cfg.ControlPlaneURL)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("webhook server stopped", "error", err)
		os.Exit(1)
	}
}
