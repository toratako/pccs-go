// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package config loads PCCS settings and creates private local configurations.
package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config uses durations as strings so its JSON remains easy to edit.
// Token hashes are SHA-512 hex digests; raw tokens are never stored in config.
type Config struct {
	Listen                string `json:"listen"`
	DataDir               string `json:"data_dir"`
	Mode                  string `json:"mode"`
	PCSURL                string `json:"pcs_url"`
	APIKey                string `json:"api_key"`
	Proxy                 string `json:"proxy"`
	TLSCert               string `json:"tls_cert"`
	TLSKey                string `json:"tls_key"`
	UserTokenHash         string `json:"user_token_hash"`
	AdminTokenHash        string `json:"admin_token_hash"`
	CollateralRootCA      string `json:"collateral_root_ca"`
	LogLevel              string `json:"log_level"`
	UpstreamTimeout       string `json:"upstream_timeout"`
	RefreshInterval       string `json:"refresh_interval"`
	ShutdownTimeout       string `json:"shutdown_timeout"`
	MaxBodyBytes          int64  `json:"max_body_bytes"`
	MaxCacheBytes         int64  `json:"max_cache_bytes"`
	MaxConcurrentRequests int    `json:"max_concurrent_requests"`
}

// Default returns settings before file and environment overrides.
func Default() Config {
	return Config{
		Listen:                "127.0.0.1:8081",
		DataDir:               "data",
		Mode:                  "LAZY",
		PCSURL:                "https://api.trustedservices.intel.com/sgx/certification/v4/",
		LogLevel:              "info",
		UpstreamTimeout:       "120s",
		RefreshInterval:       "24h",
		ShutdownTimeout:       "30s",
		MaxBodyBytes:          2 << 20,
		MaxCacheBytes:         128 << 20,
		MaxConcurrentRequests: 128,
	}
}

// Load applies defaults, strict JSON settings, then PCCS_* environment values.
// File paths are relative to the config file; environment paths are relative
// to the current directory. Empty environment values are explicit overrides.
func Load(path string) (Config, error) {
	return LoadWithOverrides(path, nil)
}

// LoadWithOverrides applies command-line settings after file and environment
// settings, before validating the effective configuration.
func LoadWithOverrides(path string, override func(*Config)) (Config, error) {
	var zero Config
	f, err := os.Open(path)
	if err != nil {
		return zero, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	cfg := Default()
	decoded := &cfg
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return zero, errors.New("configuration must contain a JSON object with known fields and valid types")
	}
	if decoded == nil {
		return zero, errors.New("configuration must contain a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, errors.New("configuration contains trailing data")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return zero, errors.New("could not resolve configuration paths")
	}
	paths := []*string{&cfg.DataDir, &cfg.TLSCert, &cfg.TLSKey, &cfg.CollateralRootCA}
	for _, value := range paths {
		*value = resolvePath(base, *value)
	}
	fields := []struct {
		name string
		dst  *string
		path bool
	}{
		{"PCCS_LISTEN", &cfg.Listen, false},
		{"PCCS_DATA_DIR", &cfg.DataDir, true},
		{"PCCS_MODE", &cfg.Mode, false},
		{"PCCS_PCS_URL", &cfg.PCSURL, false},
		{"PCCS_API_KEY", &cfg.APIKey, false},
		{"PCCS_PROXY", &cfg.Proxy, false},
		{"PCCS_TLS_CERT", &cfg.TLSCert, true},
		{"PCCS_TLS_KEY", &cfg.TLSKey, true},
		{"PCCS_USER_TOKEN_HASH", &cfg.UserTokenHash, false},
		{"PCCS_ADMIN_TOKEN_HASH", &cfg.AdminTokenHash, false},
		{"PCCS_COLLATERAL_ROOT_CA", &cfg.CollateralRootCA, true},
		{"PCCS_LOG_LEVEL", &cfg.LogLevel, false},
		{"PCCS_UPSTREAM_TIMEOUT", &cfg.UpstreamTimeout, false},
		{"PCCS_REFRESH_INTERVAL", &cfg.RefreshInterval, false},
		{"PCCS_SHUTDOWN_TIMEOUT", &cfg.ShutdownTimeout, false},
	}
	for _, field := range fields {
		if value, ok := os.LookupEnv(field.name); ok {
			if field.path && value != "" {
				value, err = filepath.Abs(value)
				if err != nil {
					return zero, errors.New("could not resolve environment path")
				}
			}
			*field.dst = value
		}
	}
	if value, ok := os.LookupEnv("PCCS_MAX_BODY_BYTES"); ok {
		cfg.MaxBodyBytes, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			return zero, errors.New("PCCS_MAX_BODY_BYTES must be an integer")
		}
	}
	if value, ok := os.LookupEnv("PCCS_MAX_CACHE_BYTES"); ok {
		cfg.MaxCacheBytes, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			return zero, errors.New("PCCS_MAX_CACHE_BYTES must be an integer")
		}
	}
	if value, ok := os.LookupEnv("PCCS_MAX_CONCURRENT_REQUESTS"); ok {
		cfg.MaxConcurrentRequests, err = strconv.Atoi(value)
		if err != nil {
			return zero, errors.New("PCCS_MAX_CONCURRENT_REQUESTS must be an integer")
		}
	}
	if override != nil {
		override(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		return zero, err
	}
	return cfg, nil
}

func resolvePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// Validate checks settings without exposing secret values in its errors.
// Duration limits are 1 hour upstream, 10 minutes shutdown and 365 days refresh.
func (cfg Config) Validate() error {
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil || strings.ContainsAny(host, " /\\\t\r\n") {
		return errors.New("listen must be a host:port address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return errors.New("listen port must be between 0 and 65535")
	}
	if cfg.DataDir == "" || strings.ContainsRune(cfg.DataDir, 0) {
		return errors.New("data_dir must be a nonempty path")
	}
	switch cfg.Mode {
	case "LAZY", "REQ", "OFFLINE":
	default:
		return errors.New("mode must be LAZY, REQ or OFFLINE")
	}
	if err := validatePCSURL(cfg.PCSURL); err != nil {
		return err
	}
	for _, char := range cfg.APIKey {
		if char < 32 || char == 127 {
			return errors.New("api_key must not contain control characters")
		}
	}
	if cfg.Proxy != "" {
		u, err := url.Parse(cfg.Proxy)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Path != "" && u.Path != "/") || !validURLPort(u) {
			return errors.New("proxy must be an HTTP or HTTPS proxy URL without a query, fragment or path")
		}
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return errors.New("tls_cert and tls_key must be set together")
	}
	for _, path := range []string{cfg.TLSCert, cfg.TLSKey, cfg.CollateralRootCA} {
		if strings.ContainsRune(path, 0) {
			return errors.New("TLS and collateral CA paths must not contain NUL characters")
		}
	}
	for _, hash := range []string{cfg.UserTokenHash, cfg.AdminTokenHash} {
		if hash == "" {
			continue
		}
		if len(hash) != 128 {
			return errors.New("token hashes must be SHA-512 hex digests")
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return errors.New("token hashes must be SHA-512 hex digests")
		}
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return errors.New("log_level must be a valid slog level")
	}
	for _, field := range []struct {
		name  string
		value string
		max   time.Duration
		zero  bool
	}{
		{"upstream_timeout", cfg.UpstreamTimeout, time.Hour, false},
		{"shutdown_timeout", cfg.ShutdownTimeout, 10 * time.Minute, false},
		{"refresh_interval", cfg.RefreshInterval, 365 * 24 * time.Hour, true},
	} {
		duration, err := time.ParseDuration(field.value)
		if err != nil || duration < 0 || (!field.zero && duration == 0) || duration > field.max {
			return fmt.Errorf("%s is outside its supported duration range", field.name)
		}
	}
	if cfg.MaxBodyBytes < 1 || cfg.MaxBodyBytes > 64<<20 {
		return errors.New("max_body_bytes must be between 1 and 67108864")
	}
	if cfg.MaxCacheBytes < 1024 || cfg.MaxCacheBytes > 1<<30 {
		return errors.New("max_cache_bytes must be between 1024 and 1073741824")
	}
	if cfg.MaxConcurrentRequests < 1 || cfg.MaxConcurrentRequests > 4096 {
		return errors.New("max_concurrent_requests must be between 1 and 4096")
	}
	return nil
}

func validatePCSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || !validURLPort(u) {
		return errors.New("pcs_url must be an absolute URL without credentials, a query or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errors.New("pcs_url requires HTTPS, or HTTP on loopback for development")
}

func validURLPort(u *url.URL) bool {
	port := u.Port()
	if port == "" {
		return !strings.HasSuffix(u.Host, ":")
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}
