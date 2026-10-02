// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(args []string, input string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), args, strings.NewReader(input), &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func TestHelpAndArgumentErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"serve", "--help"}, {"platforms", "list", "--help"}, {"config", "check", "--help"}, {"refresh", "--help"}, {"token", "--help"}} {
		stdout, stderr, err := invoke(args, "")
		if err != nil || !strings.Contains(stdout, "Usage:") || stderr != "" {
			t.Fatalf("%v: stdout=%q stderr=%q err=%v", args, stdout, stderr, err)
		}
	}
	for _, args := range [][]string{{"missing"}, {"version", "extra"}, {"serve", "--unknown"}, {"platforms", "list", "--source", "[invalid]"}, {"refresh", "--fmspc", "invalid"}, {"collateral", "import"}, {"token", "hash", "secret-in-argument"}} {
		stdout, _, err := invoke(args, "")
		if err == nil || stdout != "" {
			t.Fatalf("%v: stdout=%q err=%v", args, stdout, err)
		}
		if strings.Contains(err.Error(), "secret-in-argument") {
			t.Fatal("error echoed secret argument")
		}
	}
}

func TestTokenGenerateAndHash(t *testing.T) {
	value, stderr, err := invoke([]string{"token", "generate"}, "")
	if err != nil || stderr != "" {
		t.Fatalf("generate: %v %q", err, stderr)
	}
	token := strings.TrimSuffix(value, "\n")
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("invalid token: %v", err)
	}
	value2, _, err := invoke([]string{"token", "generate"}, "")
	if err != nil || value2 == value {
		t.Fatal("tokens are not fresh")
	}
	stdout, stderr, err := invoke([]string{"token", "hash"}, token+"\r\n")
	sum := sha512.Sum512([]byte(token))
	if err != nil || stdout != hex.EncodeToString(sum[:])+"\n" || stderr != "" {
		t.Fatalf("hash: %q %q %v", stdout, stderr, err)
	}
	for _, input := range []string{"", "one\ntwo", strings.Repeat("x", 4097), "has a space"} {
		stdout, _, err := invoke([]string{"token", "hash"}, input)
		if err == nil || stdout != "" {
			t.Fatalf("invalid token accepted (%d bytes)", len(input))
		}
	}
}

func TestClientAuthenticationAndRefreshSelection(t *testing.T) {
	t.Setenv("PCCS_CONFIG", "")
	t.Setenv("PCCS_ADMIN_TOKEN", "admin-test-token")
	t.Setenv("PCCS_USER_TOKEN", "user-test-token")
	tests := []struct {
		args                                      []string
		input, method, path, query, header, token string
	}{
		{[]string{"health"}, "", "GET", "/healthz/ready", "", "", ""},
		{[]string{"platforms", "list"}, "", "GET", "/sgx/certification/v4/platforms", "source=%5B%5D", "Admin-Token", "admin-test-token"},
		{[]string{"platforms", "list", "--source", "reg"}, "", "GET", "/sgx/certification/v4/platforms", "source=reg", "Admin-Token", "admin-test-token"},
		{[]string{"platforms", "register", "--file", "-"}, `{"qe_id":"q"}`, "POST", "/sgx/certification/v4/platforms", "", "User-Token", "user-test-token"},
		{[]string{"collateral", "import", "--file", "-"}, `{}`, "PUT", "/sgx/certification/v4/platformcollateral", "", "Admin-Token", "admin-test-token"},
		{[]string{"refresh"}, "", "POST", "/sgx/certification/v4/refresh", "", "Admin-Token", "admin-test-token"},
		{[]string{"refresh", "--fmspc", "all"}, "", "POST", "/sgx/certification/v4/refresh", "fmspc=all&type=certs", "Admin-Token", "admin-test-token"},
		{[]string{"refresh", "--type", "certs", "--fmspc", "001122aabbcc"}, "", "POST", "/sgx/certification/v4/refresh", "fmspc=001122aabbcc&type=certs", "Admin-Token", "admin-test-token"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != tc.path || r.URL.RawQuery != tc.query {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				if tc.header != "" && r.Header.Get(tc.header) != tc.token {
					t.Error("wrong authentication token")
				}
				if r.Header.Get("Authorization") != "" {
					t.Error("unexpected Authorization header")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.input {
					t.Errorf("body=%q err=%v", body, err)
				}
				if tc.input != "" && r.Header.Get("Content-Type") != "application/json" {
					t.Error("JSON content type missing")
				}
				io.WriteString(w, `{"ok":true}`)
			}))
			defer srv.Close()
			args := append(append([]string{}, tc.args...), "--url", srv.URL)
			stdout, stderr, err := invoke(args, tc.input)
			if err != nil || stdout != "{\"ok\":true}\n" || stderr != "" {
				t.Fatalf("output=%q stderr=%q err=%v", stdout, stderr, err)
			}
		})
	}
}

func TestClientTLSVerification(t *testing.T) {
	t.Setenv("PCCS_CONFIG", "")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "UP") }))
	defer srv.Close()
	stdout, _, err := invoke([]string{"health", "--url", srv.URL}, "")
	if err == nil || stdout != "" {
		t.Fatal("untrusted TLS certificate was accepted")
	}
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = invoke([]string{"health", "--url", srv.URL, "--ca", ca}, "")
	if err != nil || stdout != "UP\n" {
		t.Fatalf("trusted TLS request failed: %q %v", stdout, err)
	}
}

func TestClientDoesNotFollowRedirectOrEchoFailureBody(t *testing.T) {
	t.Setenv("PCCS_CONFIG", "")
	t.Setenv("PCCS_ADMIN_TOKEN", "admin-secret")
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusUnauthorized} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://127.0.0.1:1/private?secret=value")
			w.WriteHeader(status)
			io.WriteString(w, "admin-secret")
		}))
		stdout, stderr, err := invoke([]string{"platforms", "list", "--url", srv.URL}, "")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "HTTP ") || strings.Contains(err.Error(), "secret") || stdout != "" || stderr != "" {
			t.Fatalf("status %d: output=%q stderr=%q err=%v", status, stdout, stderr, err)
		}
	}
}

func TestClientValidationBeforeRequest(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com/path", "https://example.com?secret=value"} {
		_, err := clientURL(raw, "")
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe URL accepted or echoed: %v", err)
		}
	}
	_, err := readJSON("-", strings.NewReader(`{} {}`), 100)
	if err == nil {
		t.Fatal("multiple JSON values accepted")
	}
	_, err = readJSON("-", strings.NewReader(`{"long":"value"}`), 4)
	if err == nil {
		t.Fatal("oversized JSON accepted")
	}
}

func TestTokenFileAndEnvironmentPrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PCCS_ADMIN_TOKEN", "")
	if err := os.WriteFile(filepath.Join(dir, "admin.token"), []byte("file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := loadToken("admin", filepath.Join(dir, "config.json"))
	if err != nil || value != "file-token" {
		t.Fatalf("file token: %q %v", value, err)
	}
	t.Setenv("PCCS_ADMIN_TOKEN", "env-token")
	value, err = loadToken("admin", filepath.Join(dir, "config.json"))
	if err != nil || value != "env-token" {
		t.Fatalf("env token: %q %v", value, err)
	}
}
