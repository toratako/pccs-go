// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func clearEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"LISTEN", "DATA_DIR", "MODE", "PCS_URL", "API_KEY", "PROXY", "TLS_CERT", "TLS_KEY", "USER_TOKEN_HASH", "ADMIN_TOKEN_HASH", "COLLATERAL_ROOT_CA", "LOG_LEVEL", "UPSTREAM_TIMEOUT", "REFRESH_INTERVAL", "SHUTDOWN_TIMEOUT", "MAX_BODY_BYTES", "MAX_CACHE_BYTES", "MAX_CONCURRENT_REQUESTS",
	} {
		name = "PCCS_" + name
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultsAndFilePaths(t *testing.T) {
	clearEnvironment(t)
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, `{"listen":"127.0.0.1:0","mode":"OFFLINE","tls_cert":"server.crt","tls_key":"server.key","collateral_root_ca":"roots.pem"}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:0" || cfg.Mode != "OFFLINE" || cfg.UpstreamTimeout != "120s" || cfg.MaxBodyBytes != 2<<20 {
		t.Fatalf("file/default precedence failed: listen=%s mode=%s timeout=%s limit=%d", cfg.Listen, cfg.Mode, cfg.UpstreamTimeout, cfg.MaxBodyBytes)
	}
	base := filepath.Dir(path)
	for got, want := range map[string]string{cfg.DataDir: filepath.Join(base, "data"), cfg.TLSCert: filepath.Join(base, "server.crt"), cfg.TLSKey: filepath.Join(base, "server.key"), cfg.CollateralRootCA: filepath.Join(base, "roots.pem")} {
		if got != want {
			t.Errorf("resolved path = %s, want %s", got, want)
		}
	}
	if _, err := Load(filepath.Join(base, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v", err)
	}
}

func TestCommandLineOverridesValidateEffectiveConfiguration(t *testing.T) {
	clearEnvironment(t)
	path := writeConfig(t, `{"listen":"invalid-file-listen"}`)
	t.Setenv("PCCS_MODE", "invalid-environment-mode")
	if _, err := Load(path); err == nil {
		t.Fatal("invalid settings accepted without overrides")
	}
	cfg, err := LoadWithOverrides(path, func(cfg *Config) {
		cfg.Listen = "127.0.0.1:0"
		cfg.Mode = "OFFLINE"
	})
	if err != nil || cfg.Mode != "OFFLINE" || cfg.Listen != "127.0.0.1:0" {
		t.Fatalf("effective CLI configuration was not used: %v", err)
	}
	if _, err := LoadWithOverrides(path, func(cfg *Config) {
		cfg.Listen = "127.0.0.1:0"
		cfg.Mode = "bad-CLI-mode"
	}); err == nil {
		t.Fatal("invalid command-line setting accepted")
	}
}

func TestEnvironmentPrecedence(t *testing.T) {
	clearEnvironment(t)
	path := writeConfig(t, `{"listen":"127.0.0.1:99","mode":"LAZY","api_key":"file-secret","data_dir":"file-data","proxy":"https://file-proxy.example.com","tls_cert":"file.crt","tls_key":"file.key"}`)
	hash := strings.Repeat("ab", 64)
	for name, value := range map[string]string{
		"PCCS_LISTEN": "[::1]:0", "PCCS_MODE": "REQ", "PCCS_PCS_URL": "http://127.0.0.1:8080/sgx/certification/v4/", "PCCS_API_KEY": "environment-secret", "PCCS_PROXY": "", "PCCS_DATA_DIR": "environment-data", "PCCS_TLS_CERT": "environment.crt", "PCCS_TLS_KEY": "environment.key", "PCCS_COLLATERAL_ROOT_CA": "environment-ca.pem", "PCCS_USER_TOKEN_HASH": hash, "PCCS_ADMIN_TOKEN_HASH": hash, "PCCS_LOG_LEVEL": "debug", "PCCS_UPSTREAM_TIMEOUT": "15s", "PCCS_REFRESH_INTERVAL": "0s", "PCCS_SHUTDOWN_TIMEOUT": "5s", "PCCS_MAX_BODY_BYTES": "1234",
	} {
		t.Setenv(name, value)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "[::1]:0" || cfg.Mode != "REQ" || cfg.PCSURL != "http://127.0.0.1:8080/sgx/certification/v4/" || cfg.APIKey != "environment-secret" || cfg.Proxy != "" || cfg.UserTokenHash != hash || cfg.AdminTokenHash != hash || cfg.LogLevel != "debug" || cfg.UpstreamTimeout != "15s" || cfg.RefreshInterval != "0s" || cfg.ShutdownTimeout != "5s" || cfg.MaxBodyBytes != 1234 {
		t.Fatal("environment overrides were not applied")
	}
	for got, relative := range map[string]string{cfg.DataDir: "environment-data", cfg.TLSCert: "environment.crt", cfg.TLSKey: "environment.key", cfg.CollateralRootCA: "environment-ca.pem"} {
		want, err := filepath.Abs(relative)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("environment path = %s, want %s", got, want)
		}
	}
	t.Setenv("PCCS_MAX_BODY_BYTES", "secret-invalid-number")
	if _, err := Load(path); err == nil || strings.Contains(err.Error(), "secret-invalid-number") {
		t.Fatalf("invalid environment number leaked: %v", err)
	}
}

func TestResourceLimits(t *testing.T) {
	clearEnvironment(t)
	path := writeConfig(t, `{}`)
	t.Setenv("PCCS_MAX_CACHE_BYTES", "1048576")
	t.Setenv("PCCS_MAX_CONCURRENT_REQUESTS", "8")
	cfg, err := Load(path)
	if err != nil || cfg.MaxCacheBytes != 1048576 || cfg.MaxConcurrentRequests != 8 {
		t.Fatalf("resource limit environment overrides: %v", err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.MaxCacheBytes = 0 },
		func(c *Config) { c.MaxCacheBytes = (1 << 30) + 1 },
		func(c *Config) { c.MaxConcurrentRequests = 0 },
		func(c *Config) { c.MaxConcurrentRequests = 4097 },
	} {
		invalid := cfg
		change(&invalid)
		if invalid.Validate() == nil {
			t.Error("invalid resource limit accepted")
		}
	}
	t.Setenv("PCCS_MAX_CACHE_BYTES", "not-an-integer")
	if _, err := Load(path); err == nil {
		t.Error("invalid capacity environment accepted")
	}
}

func TestStrictJSONAndSecretSafeErrors(t *testing.T) {
	clearEnvironment(t)
	for _, content := range []string{
		`{"unknown-secret-field":"sensitive-value"}`, `{"api_key":123}`, `{"api_key":"sensitive-value"`, `{} {}`, `{} garbage`, `null`, `[]`, `"sensitive-value"`,
	} {
		path := writeConfig(t, content)
		if _, err := Load(path); err == nil || strings.Contains(err.Error(), "sensitive-value") || strings.Contains(err.Error(), "unknown-secret-field") {
			t.Fatalf("invalid JSON accepted or leaked content: %v", err)
		}
	}
}

func TestValidation(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"listen syntax":    func(c *Config) { c.Listen = "localhost" },
		"listen port":      func(c *Config) { c.Listen = "localhost:65536" },
		"data directory":   func(c *Config) { c.DataDir = "" },
		"mode":             func(c *Config) { c.Mode = "lazy" },
		"URL credentials":  func(c *Config) { c.PCSURL = "https://name:sensitive-value@example.com/" },
		"URL query":        func(c *Config) { c.PCSURL += "?token=sensitive-value" },
		"URL fragment":     func(c *Config) { c.PCSURL += "#sensitive-value" },
		"URL remote HTTP":  func(c *Config) { c.PCSURL = "http://example.com/" },
		"URL bad port":     func(c *Config) { c.PCSURL = "https://example.com:99999/" },
		"proxy query":      func(c *Config) { c.Proxy = "http://example.com/?token=sensitive-value" },
		"proxy invalid":    func(c *Config) { c.Proxy = "sensitive-value" },
		"header control":   func(c *Config) { c.APIKey = "sensitive-value\r\n" },
		"TLS pair":         func(c *Config) { c.TLSCert = "server.crt" },
		"hash length":      func(c *Config) { c.AdminTokenHash = "sensitive-value" },
		"hash encoding":    func(c *Config) { c.UserTokenHash = strings.Repeat("z", 128) },
		"log level":        func(c *Config) { c.LogLevel = "sensitive-value" },
		"upstream zero":    func(c *Config) { c.UpstreamTimeout = "0s" },
		"upstream maximum": func(c *Config) { c.UpstreamTimeout = "2h" },
		"upstream parse":   func(c *Config) { c.UpstreamTimeout = "sensitive-value" },
		"shutdown zero":    func(c *Config) { c.ShutdownTimeout = "0s" },
		"shutdown maximum": func(c *Config) { c.ShutdownTimeout = "11m" },
		"refresh negative": func(c *Config) { c.RefreshInterval = "-1s" },
		"refresh maximum":  func(c *Config) { c.RefreshInterval = "8761h" },
		"body zero":        func(c *Config) { c.MaxBodyBytes = 0 },
		"body maximum":     func(c *Config) { c.MaxBodyBytes = 1<<63 - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			change(&cfg)
			if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), "sensitive-value") {
				t.Fatalf("invalid configuration accepted or leaked secret: %v", err)
			}
		})
	}
	for _, raw := range []string{"http://localhost:8080/", "http://127.0.0.1/", "http://[::1]/", "https://example.com/"} {
		cfg := Default()
		cfg.PCSURL = raw
		cfg.RefreshInterval = "0"
		cfg.MaxBodyBytes = 64 << 20
		cfg.AdminTokenHash = strings.Repeat("AB", 64)
		cfg.Proxy = "http://name:password@localhost:8080"
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid configuration rejected: %v", err)
		}
	}
}

func TestInitializeCredentialsAndNoOverwrite(t *testing.T) {
	clearEnvironment(t)
	dir := filepath.Join(t.TempDir(), "pccs")
	path, err := Initialize(dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "config.json") {
		t.Fatalf("config path = %s", path)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw Config
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.DataDir != "data" || raw.TLSCert != "server.crt" || raw.TLSKey != "server.key" {
		t.Fatal("generated configuration paths are not relative")
	}
	var previous string
	for name, expected := range map[string]string{"admin.token": cfg.AdminTokenHash, "user.token": cfg.UserTokenHash} {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		token := strings.TrimSpace(string(content))
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(decoded) != 32 || token == previous {
			t.Fatalf("invalid or duplicate generated token in %s", name)
		}
		previous = token
		hash := sha512.Sum512([]byte(token))
		if hex.EncodeToString(hash[:]) != expected || strings.Contains(string(data), token) {
			t.Fatalf("incorrect token hash or raw token in configuration: %s", name)
		}
	}
	pair, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().BitSize != 256 {
		t.Fatal("leaf key is not ECDSA P-256")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("generated CA cannot be parsed")
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host})
		if err != nil {
			t.Errorf("TLS chain verification for %s: %v", host, err)
			continue
		}
		if len(leaf.AuthorityKeyId) == 0 || hex.EncodeToString(leaf.AuthorityKeyId) != hex.EncodeToString(chains[0][1].SubjectKeyId) {
			t.Fatal("leaf authority key identifier must match its CA for strict TLS clients")
		}
	}
	if remaining := time.Until(leaf.NotAfter); remaining < 364*24*time.Hour || remaining > 367*24*time.Hour {
		t.Fatal("certificate validity is not approximately one year")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 {
		t.Fatalf("unexpected generated files: %d", len(entries))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("directory permissions: %v", err)
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("file permissions on %s: %v", entry.Name(), err)
			}
		}
	}
	if _, err := Initialize(dir); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing directory initialization = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(data) {
		t.Fatal("existing configuration was overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("CA private key was saved")
	}
}
