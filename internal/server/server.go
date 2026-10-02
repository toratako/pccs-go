/*
 * Copyright (C) 2026 toratako and contributors
 * Portions derived from Intel PCCS:
 * Copyright (C) 2011-2026 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

// Package server exposes the PCCS v4 API and health probes as an HTTP handler.
// Version 3 routes return HTTP 410 because PCS v3 has reached end of life.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/toratako/pccs-go/internal/service"
	"github.com/toratako/pccs-go/internal/store"
)

// DefaultMaxBodyBytes matches the original server's default JSON body limit.
const DefaultMaxBodyBytes int64 = 2 << 20

// Config stores SHA-512 token hashes, never plaintext tokens. Empty hashes
// disable access to the associated protected endpoints. Zero MaxBodyBytes
// selects DefaultMaxBodyBytes.
type Config struct {
	UserTokenHash         string
	AdminTokenHash        string
	MaxBodyBytes          int64
	MaxConcurrentRequests int
	RequestTimeout        time.Duration
}

// Backend implements the operations used by the API. Check must perform a real
// read of the store, without running migrations or making upstream requests.
type Backend interface {
	Get(context.Context, string, string, url.Values) (service.Response, error)
	Register(context.Context, service.Platform, string) error
	Platforms(context.Context, string) ([]service.Platform, error)
	Import(context.Context, []byte) error
	Refresh(context.Context, string, string) error
	PutPolicy(context.Context, []byte) (string, error)
	Policies(context.Context, string) (string, error)
	Check() error
}

type handler struct {
	backend             Backend
	logger              *slog.Logger
	userHash, adminHash []byte
	maxBodyBytes        int64
	slots               chan struct{}
	requestTimeout      time.Duration
}

// New validates configuration and returns a handler. Listening, TLS, and
// graceful shutdown remain the caller's responsibility.
func New(cfg Config, backend Backend, logger *slog.Logger) (http.Handler, error) {
	if backend == nil {
		return nil, errors.New("HTTP backend is required")
	}
	if cfg.MaxBodyBytes < 0 {
		return nil, errors.New("HTTP body limit must be nonnegative")
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.MaxConcurrentRequests < 0 || cfg.MaxConcurrentRequests > 4096 || cfg.RequestTimeout < 0 {
		return nil, errors.New("invalid HTTP concurrency limit or request timeout")
	}
	if cfg.MaxConcurrentRequests == 0 {
		cfg.MaxConcurrentRequests = 128
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 5 * time.Minute
	}
	decodeHash := func(value string) ([]byte, error) {
		if value == "" {
			return nil, nil
		}
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha512.Size {
			return nil, errors.New("token hash must contain exactly 128 hexadecimal characters")
		}
		return decoded, nil
	}
	userHash, err := decodeHash(cfg.UserTokenHash)
	if err != nil {
		return nil, fmt.Errorf("UserTokenHash: %w", err)
	}
	adminHash, err := decodeHash(cfg.AdminTokenHash)
	if err != nil {
		return nil, fmt.Errorf("AdminTokenHash: %w", err)
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &handler{backend: backend, logger: logger, userHash: userHash, adminHash: adminHash, maxBodyBytes: cfg.MaxBodyBytes, slots: make(chan struct{}, cfg.MaxConcurrentRequests), requestTimeout: cfg.RequestTimeout}, nil
}

type route struct {
	product, endpoint, allow string
}

func findRoute(path string) (route, bool) {
	if strings.HasPrefix(path, "/healthz/") {
		endpoint := strings.TrimPrefix(path, "/healthz/")
		if endpoint == "live" || endpoint == "ready" || endpoint == "startup" {
			return route{"health", endpoint, "GET, HEAD"}, true
		}
		return route{}, false
	}
	for _, product := range []string{"sgx", "tdx"} {
		prefix := "/" + product + "/certification/v4/"
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		endpoint := strings.TrimPrefix(path, prefix)
		if product == "tdx" {
			if endpoint == "tcb" || endpoint == "qe/identity" {
				return route{product, endpoint, "GET, HEAD"}, true
			}
			return route{}, false
		}
		allow := "GET, HEAD"
		switch endpoint {
		case "pckcert", "pckcrl", "tcb", "qe/identity", "qve/identity", "rootcacrl", "crl":
		case "platforms":
			allow = "GET, POST"
		case "platformcollateral":
			allow = "PUT"
		case "refresh":
			allow = "GET, POST"
		case "appraisalpolicy":
			allow = "GET, HEAD, PUT"
		default:
			return route{}, false
		}
		return route{product, endpoint, allow}, true
	}
	return route{}, false
}

type responseWriter struct {
	http.ResponseWriter
	status int
	head   bool
}

func (w *responseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.head {
		return len(body), nil
	}
	return w.ResponseWriter.Write(body)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	written := &responseWriter{ResponseWriter: w, head: r.Method == http.MethodHead}
	var requestIDBytes [16]byte
	if _, err := rand.Read(requestIDBytes[:]); err != nil {
		writeStatus(written, http.StatusInternalServerError)
		return
	}
	requestID := hex.EncodeToString(requestIDBytes[:])
	w.Header().Set("Request-ID", requestID)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	matched, ok := findRoute(r.URL.Path)
	logRoute := "unknown"
	if ok {
		logRoute = matched.product + "/" + matched.endpoint
	}
	logMethod := r.Method
	switch logMethod {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodPatch:
	default:
		logMethod = "OTHER"
	}
	defer func() {
		if recover() != nil {
			if written.status == 0 {
				writeStatus(written, http.StatusInternalServerError)
			}
			h.logger.Error("request handler panic", "request_id", requestID, "route", logRoute)
		}
		h.logger.Info("HTTP request", "request_id", requestID, "method", logMethod, "route", logRoute, "status", written.status, "duration_ms", time.Since(started).Milliseconds())
	}()
	if r.URL.Path == "/sgx/certification/v3" || strings.HasPrefix(r.URL.Path, "/sgx/certification/v3/") || r.URL.Path == "/tdx/certification/v3" || strings.HasPrefix(r.URL.Path, "/tdx/certification/v3/") {
		writeStatus(written, http.StatusGone)
		return
	}
	if !ok {
		writeStatus(written, http.StatusNotFound)
		return
	}
	if !strings.Contains(", "+matched.allow+", ", ", "+r.Method+", ") {
		w.Header().Set("Allow", matched.allow)
		writeStatus(written, http.StatusMethodNotAllowed)
		return
	}
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	if !h.authorized(r, matched.endpoint, method) {
		writeStatus(written, http.StatusUnauthorized)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeStatus(written, http.StatusBadRequest)
		return
	}
	for _, values := range query {
		if len(values) != 1 {
			writeStatus(written, http.StatusBadRequest)
			return
		}
	}
	if !validateQuery(matched.endpoint, method, query) {
		writeStatus(written, http.StatusBadRequest)
		return
	}
	filterQuery(matched.endpoint, method, query)
	// Reject excess work rather than queueing unbounded handlers behind PCS.
	// Liveness stays available while the bounded backend work is saturated.
	if matched.product != "health" || matched.endpoint != "live" {
		select {
		case h.slots <- struct{}{}:
			defer func() { <-h.slots }()
		default:
			w.Header().Set("Retry-After", "1")
			writeStatus(written, http.StatusServiceUnavailable)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	if err := h.dispatch(written, r, matched, method, query); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		} else if errors.Is(err, context.Canceled) {
			status = http.StatusServiceUnavailable
		}
		if errors.Is(err, store.ErrCapacity) {
			status = http.StatusServiceUnavailable
			h.logger.Warn("cache capacity limit reached", "request_id", requestID)
		}
		var statusError *service.StatusError
		if errors.As(err, &statusError) {
			if _, known := statusMessages[statusError.StatusCode]; known && statusError.StatusCode >= 400 {
				status = statusError.StatusCode
			}
		}
		var bodyError *http.MaxBytesError
		if errors.As(err, &bodyError) {
			status = http.StatusRequestEntityTooLarge
		}
		if written.status == 0 {
			writeStatus(written, status)
		}
	}
}

func (h *handler) authorized(r *http.Request, endpoint, method string) bool {
	var expected []byte
	var header string
	switch {
	case endpoint == "platforms" && method == http.MethodPost:
		expected, header = h.userHash, "User-Token"
	case endpoint == "platforms", endpoint == "platformcollateral", endpoint == "refresh", endpoint == "appraisalpolicy" && method == http.MethodPut:
		expected, header = h.adminHash, "Admin-Token"
	default:
		return true
	}
	values := r.Header.Values(header)
	if len(expected) != sha512.Size || len(values) != 1 || values[0] == "" || len(values[0]) > 4096 {
		return false
	}
	actual := sha512.Sum512([]byte(values[0]))
	// Both operands are exactly 64 bytes. Input validation depends on public
	// framing/length; comparison never exits early based on the secret digest.
	return subtle.ConstantTimeCompare(actual[:], expected) == 1
}

func (h *handler) dispatch(w http.ResponseWriter, r *http.Request, route route, method string, query url.Values) error {
	if route.product == "health" {
		h.health(w, route.endpoint)
		return nil
	}
	switch route.endpoint {
	case "platforms":
		if method == http.MethodPost {
			body, err := h.readObject(w, r)
			if err != nil {
				return err
			}
			platform, err := parsePlatform(body)
			if err != nil {
				return invalidRequest()
			}
			if err = h.backend.Register(r.Context(), platform, query.Get("update")); err != nil {
				return err
			}
			writeStatus(w, http.StatusOK)
			return nil
		}
		platforms, err := h.backend.Platforms(r.Context(), query.Get("source"))
		if err != nil {
			return err
		}
		if platforms == nil {
			platforms = []service.Platform{}
		}
		w.Header().Set("Platform-Count", strconv.Itoa(len(platforms)))
		return writeJSON(w, http.StatusOK, platforms)
	case "platformcollateral":
		body, err := h.readObject(w, r)
		if err != nil {
			return err
		}
		if err = h.backend.Import(r.Context(), body); err != nil {
			return err
		}
		writeStatus(w, http.StatusOK)
		return nil
	case "refresh":
		if err := h.backend.Refresh(r.Context(), query.Get("type"), query.Get("fmspc")); err != nil {
			return err
		}
		writeStatus(w, http.StatusOK)
		return nil
	case "appraisalpolicy":
		if method == http.MethodPut {
			body, err := h.readObject(w, r)
			if err != nil {
				return err
			}
			if !validPolicy(body) {
				return invalidRequest()
			}
			id, err := h.backend.PutPolicy(r.Context(), body)
			if err != nil {
				return err
			}
			writeText(w, http.StatusOK, id)
			return nil
		}
		policies, err := h.backend.Policies(r.Context(), query.Get("fmspc"))
		if err != nil {
			return err
		}
		if policies == "" {
			writeStatus(w, http.StatusNotFound)
			return nil
		}
		writeText(w, http.StatusOK, policies)
		return nil
	default:
		response, err := h.backend.Get(r.Context(), route.product, route.endpoint, query)
		if err != nil {
			return err
		}
		for name, values := range response.Header {
			if collateralHeader(name) {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(response.Body)))
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(response.Body)
		return err
	}
}

func collateralHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Content-Type", "Sgx-Tcbm", "Sgx-Fmspc", "Sgx-Pck-Certificate-Ca-Type", "Sgx-Pck-Certificate-Issuer-Chain", "Sgx-Pck-Crl-Issuer-Chain", "Tcb-Info-Issuer-Chain", "Sgx-Tcb-Info-Issuer-Chain", "Sgx-Enclave-Identity-Issuer-Chain":
		return true
	}
	return false
}

func (h *handler) health(w http.ResponseWriter, endpoint string) {
	started := time.Now()
	status := http.StatusOK
	response := map[string]string{"status": "UP", "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
	if endpoint != "live" {
		err := h.backend.Check()
		if endpoint == "ready" {
			response["db"] = "CONNECTED"
			response["latency"] = fmt.Sprintf("%dms", time.Since(started).Milliseconds())
			if err != nil {
				response["status"], response["db"] = "DOWN", "DISCONNECTED"
				delete(response, "latency")
			}
		} else {
			response["status"] = "STARTED"
			if err != nil {
				response["status"] = "STARTING"
			}
		}
		if err != nil {
			status = http.StatusServiceUnavailable
		}
	}
	_ = writeJSON(w, status, response)
}

var statusMessages = map[int]string{
	200: "Operation successful.",
	400: "Invalid request parameters.",
	401: "Authentication failed.",
	404: "No cache data for this platform.",
	405: "Method not allowed.",
	410: "The Intel PCS API version 3 reached planned EOL. Accordingly, collateral from this API version cannot be retrieved any longer.",
	413: "Content too large.",
	415: "Unsupported media type.",
	460: "The integrity of the data can't be verified.",
	461: "The platform was not found in the cache.",
	462: "Certificates are not available for certain TCBs.",
	500: "Internal server error occurred.",
	502: "Unable to retrieve the collateral from the Intel SGX PCS.",
	503: "Server is currently unable to process the request.",
	504: "Request processing timed out.",
}

func writeStatus(w http.ResponseWriter, status int) { writeText(w, status, statusMessages[status]) }

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func writeJSON(w http.ResponseWriter, status int, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, err = w.Write(body)
	return err
}

func invalidRequest() error { return &service.StatusError{StatusCode: http.StatusBadRequest} }
