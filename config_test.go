package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv(envConfig, "")
	t.Setenv(envHTTPAddr, "")
	t.Setenv(envAlgorithm, "")
	t.Setenv(envSecretKeyFile, "")
	t.Setenv(envPublicKeyFile, "")
	t.Setenv(envLogLevel, "")

	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	cfg, used, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if used != "" {
		t.Fatalf("unexpected config path %q", used)
	}
	if cfg.HTTPAddr != ":8080" || cfg.Algorithm != "ML-DSA-65" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadConfigFileThenEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("http_addr: \":9090\"\nalgorithm: ML-DSA-65\nlog_level: warn\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(envHTTPAddr, ":7070")
	t.Setenv(envAlgorithm, "ML-DSA-87")
	t.Setenv(envLogLevel, "debug")

	cfg, used, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if used != path {
		t.Fatalf("used path = %q, want %q", used, path)
	}
	if cfg.HTTPAddr != ":7070" {
		t.Fatalf("http_addr = %q, want env override", cfg.HTTPAddr)
	}
	if cfg.Algorithm != "ML-DSA-87" {
		t.Fatalf("algorithm = %q, want env override", cfg.Algorithm)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("log_level = %q, want env override", cfg.LogLevel)
	}
}

func TestConfigValidateKeyFilesTogether(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKeyFile = "secret.bin"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when only secret_key_file is set")
	}
}
