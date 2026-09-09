package config

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	envConfig        = "PQC_CONFIG"
	envHTTPAddr      = "PQC_HTTP_ADDR"
	envAlgorithm     = "PQC_ALGORITHM"
	envSecretKeyFile = "PQC_SECRET_KEY_FILE"
	envPublicKeyFile = "PQC_PUBLIC_KEY_FILE"
	envLogLevel      = "PQC_LOG_LEVEL"
)

var defaultConfigPaths = []string{"config.yaml", "configs/config.yaml"}

// Config is loaded from a YAML file, then overridden by environment variables.
type Config struct {
	HTTPAddr      string `yaml:"http_addr"`
	Algorithm     string `yaml:"algorithm"`
	SecretKeyFile string `yaml:"secret_key_file"`
	PublicKeyFile string `yaml:"public_key_file"`
	LogLevel      string `yaml:"log_level"`
}

func Default() Config {
	return Config{
		HTTPAddr:  ":8080",
		Algorithm: "ML-DSA-65",
		LogLevel:  "info",
	}
}

func ParseFlags(args []string) (configPath string, err error) {
	fs := flag.NewFlagSet("qday-pqc-server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&configPath, "config", "", "YAML config path (env "+envConfig+")")
	err = fs.Parse(args)
	return configPath, err
}

func Load(explicitPath string) (Config, string, error) {
	cfg := Default()
	path := explicitPath
	if path == "" {
		path = os.Getenv(envConfig)
	}

	usedPath := ""
	switch {
	case path != "":
		if err := loadYAMLFile(path, &cfg); err != nil {
			return Config{}, "", fmt.Errorf("load config %s: %w", path, err)
		}
		usedPath = path
	default:
		if found, err := loadDefaultFile(&cfg); err != nil {
			return Config{}, "", err
		} else {
			usedPath = found
		}
	}

	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, usedPath, err
	}
	return cfg, usedPath, nil
}

func loadDefaultFile(cfg *Config) (string, error) {
	for _, path := range defaultConfigPaths {
		if !fileExists(path) {
			continue
		}
		if err := loadYAMLFile(path, cfg); err != nil {
			return "", fmt.Errorf("load %s: %w", path, err)
		}
		return path, nil
	}
	return "", nil
}

func loadYAMLFile(path string, cfg *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, cfg)
}

func applyEnv(cfg *Config) {
	if v := os.Getenv(envHTTPAddr); v != "" {
		cfg.HTTPAddr = v
	}
	if v := os.Getenv(envAlgorithm); v != "" {
		cfg.Algorithm = v
	}
	if v := os.Getenv(envSecretKeyFile); v != "" {
		cfg.SecretKeyFile = v
	}
	if v := os.Getenv(envPublicKeyFile); v != "" {
		cfg.PublicKeyFile = v
	}
	if v := os.Getenv(envLogLevel); v != "" {
		cfg.LogLevel = v
	}
}

func (c Config) SlogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
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

func (c Config) Validate() error {
	if strings.TrimSpace(c.HTTPAddr) == "" {
		return fmt.Errorf("http_addr is required")
	}
	if strings.TrimSpace(c.Algorithm) == "" {
		return fmt.Errorf("algorithm is required")
	}
	if (c.SecretKeyFile == "") != (c.PublicKeyFile == "") {
		return fmt.Errorf("secret_key_file and public_key_file must be set together")
	}
	switch strings.ToLower(c.LogLevel) {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log_level %q", c.LogLevel)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
