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

	"github.com/open-quantum-safe/liboqs-go/oqs"

	"github.com/qday-io/qday-pqc-server/internal/config"
	"github.com/qday-io/qday-pqc-server/internal/server"
	"github.com/qday-io/qday-pqc-server/internal/signer"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("exit", "err", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	configPath, err := config.ParseFlags(args)
	if err != nil {
		return err
	}

	cfg, usedPath, err := config.Load(configPath)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.SlogLevel()})))
	if usedPath != "" {
		slog.Info("loaded config file", "path", usedPath)
	}

	s, err := signer.LoadOrGenerate(cfg.Algorithm, cfg.SecretKeyFile, cfg.PublicKeyFile)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.New(s),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("qday-pqc-server listening",
			"addr", cfg.HTTPAddr,
			"algorithm", s.Algorithm(),
			"liboqs", oqs.LiboqsVersion(),
		)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
