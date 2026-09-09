package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("exit", "err", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	configPath, err := ParseFlags(args)
	if err != nil {
		return err
	}

	cfg, usedPath, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)})))

	if usedPath != "" {
		slog.Info("loaded config file", "path", usedPath)
	}

	signer, err := LoadOrGenerateSigner(cfg)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           NewServer(signer),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("qday-pqc-server listening",
			"addr", cfg.HTTPAddr,
			"algorithm", signer.Algorithm(),
			"liboqs", oqs.LiboqsVersion(),
		)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
