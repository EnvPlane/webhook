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

	webhookserver "github.com/envpilot/webhook/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := webhookserver.ConfigFromEnv()
	application, err := webhookserver.New(cfg, nil, logger)
	if err != nil {
		logger.Error("invalid webhook configuration", "error", err)
		os.Exit(1)
	}

	server := &http.Server{Addr: cfg.Addr, Handler: application.Routes(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()

	logger.Info("envpilot webhook started", "address", cfg.Addr, "control_plane_url", cfg.ControlPlaneURL)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("webhook server stopped", "error", err)
		os.Exit(1)
	}
}
