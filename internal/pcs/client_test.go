// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package pcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, server *httptest.Server, limit int64) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: server.URL + "/sgx/certification/v4/", APIKey: "test-subscription-key", MaxResponseBytes: limit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.httpClient.CloseIdleConnections)
	return c
}

func TestFetchProductPathsAndHeaders(t *testing.T) {
	for _, tc := range []struct {
		product, endpoint string
		auth              bool
	}{
		{"sgx", "pckcerts", true},
		{"sgx", "pckcrl", false},
		{"sgx", "qve/identity", false},
		{"tdx", "tcb", false},
		{"tdx", "qe/identity", false},
	} {
		t.Run(tc.product+"/"+tc.endpoint, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/"+tc.product+"/certification/v4/"+tc.endpoint {
					t.Errorf("unexpected method/path: %s %s", r.Method, r.URL.Path)
				}
				if r.URL.Query().Get("fmspc") != "a+b &c" || r.URL.Query().Get("update") != "early" {
					t.Errorf("query was not encoded: %q", r.URL.RawQuery)
				}
				if got := r.Header.Get(subscriptionKeyHeader); (got == "test-subscription-key") != tc.auth {
					t.Errorf("subscription header = %q, auth = %t", got, tc.auth)
				}
				w.Header().Set("SGX-TCB-Info-Issuer-Chain", "issuer-chain")
				w.Header().Set("Request-ID", "request-123")
				io.WriteString(w, "collateral")
			}))
			defer server.Close()
			c := newTestClient(t, server, 0)
			res, err := c.Fetch(context.Background(), tc.product, tc.endpoint, url.Values{"fmspc": {"a+b &c"}, "update": {"early"}})
			if err != nil || res.StatusCode != http.StatusOK || string(res.Body) != "collateral" || res.Header.Get("sgx-tcb-info-issuer-chain") != "issuer-chain" {
				t.Fatalf("response = %+v, err = %v", res, err)
			}
		})
	}
}

func TestFetchPCKCertificates(t *testing.T) {
	for _, manifest := range []string{"", "0011223344"} {
		t.Run(fmt.Sprintf("manifest=%t", manifest != ""), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/sgx/certification/v4/pckcerts" || r.Header.Get(subscriptionKeyHeader) != "test-subscription-key" {
					t.Errorf("incorrect PCK endpoint or subscription key")
				}
				if manifest == "" {
					if r.Method != http.MethodGet || r.URL.Query().Get("encrypted_ppid") != "encrypted+ppid" || r.URL.Query().Get("pceid") != "0000" {
						t.Errorf("incorrect encrypted PPID request: %s %s", r.Method, r.URL.RawQuery)
					}
				} else {
					if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
						t.Errorf("incorrect manifest request")
					}
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Errorf("decode manifest request: %v", err)
					}
					if len(body) != 2 || body["platformManifest"] != manifest || body["pceid"] != "0000" {
						t.Errorf("manifest body = %#v", body)
					}
				}
				io.WriteString(w, `[{"cert":"PEM"}]`)
			}))
			defer server.Close()
			c := newTestClient(t, server, 0)
			if _, err := c.FetchPCKCertificates(context.Background(), "encrypted+ppid", "0000", manifest); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPStatusErrorPreservesResponse(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Error-Code", "upstream-error")
				w.WriteHeader(status)
				io.WriteString(w, "failure body")
			}))
			defer server.Close()
			c := newTestClient(t, server, 0)
			res, err := c.FetchPCKCertificates(context.Background(), "", "0000", "manifest")
			var statusErr *StatusError
			if !errors.As(err, &statusErr) || statusErr.StatusCode != status || res.StatusCode != status || string(res.Body) != "failure body" || res.Header.Get("Error-Code") != "upstream-error" {
				t.Fatalf("response = %+v, err = %v", res, err)
			}
			if calls.Load() != 1 {
				t.Fatalf("POST was retried: %d calls", calls.Load())
			}
		})
	}
}

func TestRedirectDoesNotLeakCredentials(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationCalls.Add(1)
		io.WriteString(w, "unexpected")
	}))
	defer destination.Close()
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, destination.URL+"/capture", status)
			}))
			defer server.Close()
			c := newTestClient(t, server, 0)
			res, err := c.FetchPCKCertificates(context.Background(), "secret-ppid", "0000", "secret-manifest")
			var statusErr *StatusError
			if !errors.As(err, &statusErr) || res.StatusCode != status {
				t.Fatalf("redirect response = %+v, err = %v", res, err)
			}
		})
	}
	if destinationCalls.Load() != 0 {
		t.Fatalf("redirect destination received %d requests", destinationCalls.Load())
	}
}

func TestResponseSizeLimit(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("streaming=%t", streaming), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Request-ID", "bounded")
				if streaming {
					w.(http.Flusher).Flush()
				}
				io.WriteString(w, strings.Repeat("a", 11))
			}))
			defer server.Close()
			c := newTestClient(t, server, 10)
			res, err := c.Fetch(context.Background(), "sgx", "tcb", nil)
			if !errors.Is(err, ErrResponseTooLarge) || res.StatusCode != 200 || len(res.Body) != 0 || res.Header.Get("Request-ID") != "bounded" {
				t.Fatalf("oversized response = %+v, err = %v", res, err)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "1234567890") }))
	defer server.Close()
	if res, err := newTestClient(t, server, 10).Fetch(context.Background(), "sgx", "tcb", nil); err != nil || len(res.Body) != 10 {
		t.Fatalf("response exactly at limit: %+v, %v", res, err)
	}
}

func TestCRLAllowlist(t *testing.T) {
	for _, rawURL := range []string{
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl",
		"https://preproduction-certificates.trustedservices.intel.com/IntelSGXRootCA.der",
		"https://certprx.adsdcsp.com/IntelSGXRootCA.crl",
		"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor",
		"https://validation.api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform",
		"https://test.az.sgxprod.adsdcsp.com/sgx/certification/v4/pckcrl?ca=processor",
		"https://test.az.sgxnp.adsdcsp.com/sgx/certification/v12/pckcrl?ca=processor",
	} {
		if !IsAllowedCRLURL(rawURL) {
			t.Errorf("allowed URL rejected: %s", rawURL)
		}
	}
	for _, rawURL := range []string{
		"https://example.com/IntelSGXRootCA.crl",
		"http://certificates.trustedservices.intel.com/IntelSGXRootCA.crl",
		"https://certificates.trustedservices.intel.com.evil.example/IntelSGXRootCA.crl",
		"https://secret@certificates.trustedservices.intel.com/IntelSGXRootCA.crl",
		"https://certificates.trustedservices.intel.com:443/IntelSGXRootCA.crl",
		"https://certificates.trustedservices.intel.com/IntelSGXRootCAcrl",
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl/../../private",
		"https://certificates.trustedservices.intel.com/%49ntelSGXRootCA.crl",
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl#fragment",
		"https://api.trustedservices.intel.com/IntelSGXRootCA.crl",
		"https://certprx.adsdcsp.com/sgx/certification/v4/pckcrl?ca=processor",
		"https://api.adsdcsp.com/sgx/certification/v4/pckcrl?ca=processor",
		"https://api.trustedservices.intel.com/sgx/certification/v0/pckcrl?ca=processor",
		"https://api.trustedservices.intel.com/sgx/certification/v04/pckcrl?ca=processor",
		"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl",
		"https://example.com/path?url=https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl",
	} {
		if IsAllowedCRLURL(rawURL) {
			t.Errorf("disallowed URL accepted: %s", rawURL)
		}
	}
}

func TestFetchCRLNeverSendsSubscriptionKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "certificates.trustedservices.intel.com" || r.URL.Path != "/IntelSGXRootCA.crl" || r.Header.Get(subscriptionKeyHeader) != "" {
			t.Errorf("incorrect CRL destination or credentials: host = %s", r.Host)
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write([]byte{0x30, 0x02, 0x01, 0x00})
	}))
	defer server.Close()
	c := newTestClient(t, server, 0)
	// Keep hostname validation active while directing the request to a local TLS
	// fixture. Trust only the test server's certificate through its transport.
	localTransport := server.Client().Transport.(*http.Transport).Clone()
	localTransport.TLSClientConfig.ServerName = "example.com"
	originalDial := localTransport.DialContext
	if originalDial == nil {
		originalDial = http.DefaultTransport.(*http.Transport).DialContext
	}
	localTransport.DialContext = func(ctx context.Context, network, _ string) (netConn net.Conn, err error) {
		return originalDial(ctx, network, server.Listener.Addr().String())
	}
	c.httpClient.Transport = localTransport
	res, err := c.FetchCRL(context.Background(), "https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl")
	if err != nil || res.StatusCode != http.StatusOK || string(res.Body) != string([]byte{0x30, 0x02, 0x01, 0x00}) {
		t.Fatalf("CRL response = %+v, err = %v", res, err)
	}
}

func TestInvalidRequestNeverCallsUpstream(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1) }))
	defer server.Close()
	c := newTestClient(t, server, 0)
	for _, endpoint := range []string{"../pckcerts", "https://example.com/", "//example.com/", "tcb?secret=abc", "qe/%2e%2e/private"} {
		if _, err := c.Fetch(context.Background(), "sgx", endpoint, nil); err == nil {
			t.Errorf("accepted invalid endpoint %q", endpoint)
		}
	}
	if _, err := c.Fetch(context.Background(), "invalid", "tcb", nil); err == nil {
		t.Error("accepted invalid product")
	}
	if _, err := c.FetchPCKCertificates(context.Background(), "", "0000", ""); err == nil {
		t.Error("accepted missing manifest and PPID")
	}
	if _, err := c.FetchCRL(context.Background(), server.URL+"/IntelSGXRootCA.crl"); err == nil {
		t.Error("accepted untrusted CRL URL")
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid requests called upstream %d times", calls.Load())
	}
}

func TestCancellationAndSanitizedErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	c := newTestClient(t, server, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := c.Fetch(ctx, "sgx", "pckcerts", url.Values{"encrypted_ppid": {"private-ppid"}}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
	server.Close()
	_, err := c.Fetch(context.Background(), "sgx", "pckcerts", url.Values{"encrypted_ppid": {"private-ppid"}})
	if !errors.Is(err, ErrRequestFailed) || strings.Contains(err.Error(), "private-ppid") || strings.Contains(err.Error(), "test-subscription-key") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("request error = %v", err)
	}
}

func TestConfiguredTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL + "/sgx/certification/v4/", Timeout: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.httpClient.CloseIdleConnections)
	started := time.Now()
	_, err = c.Fetch(context.Background(), "sgx", "tcb", nil)
	if !errors.Is(err, ErrRequestFailed) || time.Since(started) > time.Second {
		t.Fatalf("configured timeout was not honored: %v, elapsed %s", err, time.Since(started))
	}
}

func TestExplicitProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "pcs.example.invalid" || r.URL.Path != "/sgx/certification/v4/tcb" {
			t.Errorf("unexpected proxied URL: %s", r.URL)
		}
		io.WriteString(w, "proxy-result")
	}))
	defer proxy.Close()
	c, err := New(Config{BaseURL: "http://pcs.example.invalid/sgx/certification/v4/", Proxy: proxy.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.httpClient.CloseIdleConnections)
	res, err := c.Fetch(context.Background(), "sgx", "tcb", nil)
	if err != nil || string(res.Body) != "proxy-result" {
		t.Fatalf("proxy response = %+v, err = %v", res, err)
	}
}

func TestProxyEnvironment(t *testing.T) {
	// ProxyFromEnvironment caches its environment on first use. A separate test
	// process verifies the real configuration without depending on test order.
	if os.Getenv("PCS_PROXY_TEST_CHILD") == "1" {
		c, err := New(Config{BaseURL: "http://pcs.example.invalid/sgx/certification/v4/"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.httpClient.CloseIdleConnections()
		res, err := c.Fetch(context.Background(), "sgx", "tcb", nil)
		if err != nil || string(res.Body) != "environment-proxy" {
			t.Fatalf("environment proxy response = %+v, err = %v", res, err)
		}
		return
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "pcs.example.invalid" {
			t.Errorf("unexpected proxied host: %s", r.URL.Host)
		}
		io.WriteString(w, "environment-proxy")
	}))
	defer proxy.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProxyEnvironment$")
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "REQUEST_METHOD", "PCS_PROXY_TEST_CHILD":
		default:
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "PCS_PROXY_TEST_CHILD=1", "HTTP_PROXY="+proxy.URL, "NO_PROXY=")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("proxy environment subprocess: %v\n%s", err, output)
	}
}

func TestConfigurationDefaultsAndValidation(t *testing.T) {
	c, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.httpClient.CloseIdleConnections)
	if c.baseURL.String() != DefaultBaseURL || c.httpClient.Timeout != DefaultTimeout || c.maxResponseBytes != DefaultMaxResponseBytes {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	for _, cfg := range []Config{
		{BaseURL: "https://secret@api.example.com/"},
		{BaseURL: "https://api.example.com/?key=secret"},
		{BaseURL: "file:///tmp/secret"},
		{BaseURL: "https://api.example.com/sgx/certification/v3/"},
		{Proxy: "not-a-proxy-secret"},
		{Proxy: "http://proxy.example.com/?token=secret"},
		{APIKey: "secret\r\nheader"},
		{Timeout: -1},
		{MaxResponseBytes: -1},
		{MaxResponseBytes: 1<<63 - 1},
	} {
		if _, err := New(cfg); err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("invalid config = %+v, err = %v", cfg, err)
		}
	}
}
