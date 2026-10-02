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

// Package pcs retrieves collateral from the Intel Provisioning Certification Service.
package pcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultBaseURL                = "https://api.trustedservices.intel.com/sgx/certification/v4/"
	DefaultTimeout                = 120 * time.Second
	DefaultMaxResponseBytes int64 = 16 << 20
	subscriptionKeyHeader         = "Ocp-Apim-Subscription-Key"
)

var (
	ErrResponseTooLarge     = errors.New("PCS response exceeds the configured size limit")
	ErrRequestFailed        = errors.New("PCS request failed")
	ErrResponseRead         = errors.New("PCS response could not be read")
	endpointPattern         = regexp.MustCompile(`^[a-z][a-z0-9]*(/[a-z][a-z0-9]*)*$`)
	rootHostPattern         = regexp.MustCompile(`^([a-zA-Z0-9-]*certificates\.trustedservices\.intel\.com|certprx\.adsdcsp\.com)$`)
	intermediateHostPattern = regexp.MustCompile(`^([a-zA-Z0-9-]*\.?api\.trustedservices\.intel\.com|[a-zA-Z0-9-]+\.az\.sgx(prod|np)\.adsdcsp\.com)$`)
	rootPathPattern         = regexp.MustCompile(`^/IntelSGXRootCA\.[a-zA-Z0-9._-]+$`)
	intermediatePathPattern = regexp.MustCompile(`^/sgx/certification/v[1-9][0-9]*/pckcrl$`)
)

// Config controls the upstream address, credentials, and request limits.
// Empty Proxy uses the standard HTTP_PROXY, HTTPS_PROXY, and NO_PROXY environment variables.
// Zero Timeout and MaxResponseBytes use the defaults above.
type Config struct {
	BaseURL          string
	APIKey           string
	Proxy            string
	Timeout          time.Duration
	MaxResponseBytes int64
}

// Response preserves upstream data even when the HTTP status indicates a failure.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// StatusError reports an unsuccessful upstream status without including URLs or bodies.
type StatusError struct {
	StatusCode int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("PCS returned HTTP status %d", e.StatusCode)
}

// Client is safe for concurrent use.
type Client struct {
	baseURL          *url.URL
	apiKey           string
	httpClient       *http.Client
	maxResponseBytes int64
}

func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Opaque != "" {
		return nil, errors.New("invalid PCS base URL")
	}
	if strings.Contains(base.Path, "/v3/") || strings.HasSuffix(base.Path, "/v3") {
		return nil, errors.New("PCS v3 has reached end of life")
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/"
	base.RawPath = ""
	if cfg.Timeout < 0 || cfg.MaxResponseBytes < 0 || cfg.MaxResponseBytes == math.MaxInt64 {
		return nil, errors.New("PCS timeout and response limit must be nonnegative and finite")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if strings.ContainsAny(cfg.APIKey, "\r\n") {
		return nil, errors.New("invalid PCS API key")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	if cfg.Proxy != "" {
		proxy, err := url.Parse(cfg.Proxy)
		if err != nil || proxy.Host == "" || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.RawQuery != "" || proxy.Fragment != "" || (proxy.Path != "" && proxy.Path != "/") {
			return nil, errors.New("invalid PCS proxy URL")
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	return &Client{
		baseURL:          base,
		apiKey:           cfg.APIKey,
		maxResponseBytes: cfg.MaxResponseBytes,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// Subscription keys are not standard Authorization headers: disable
			// redirects rather than risk forwarding them to another origin.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Fetch retrieves a relative PCS endpoint for "sgx" or "tdx".
func (c *Client) Fetch(ctx context.Context, product string, endpoint string, query url.Values) (Response, error) {
	u, err := c.endpointURL(product, endpoint, query)
	if err != nil {
		return Response{}, err
	}
	authenticated := endpoint == "pckcert" || endpoint == "pckcerts" || u.Hostname() == "validation.api.trustedservices.intel.com"
	return c.request(ctx, http.MethodGet, u, nil, authenticated)
}

// FetchPCKCertificates uses the manifest POST endpoint when a manifest is supplied,
// and otherwise retrieves certificates using the encrypted PPID query.
func (c *Client) FetchPCKCertificates(ctx context.Context, encPPID, pceID, manifest string) (Response, error) {
	if pceID == "" || (manifest == "" && encPPID == "") {
		return Response{}, errors.New("PCK certificate request requires PCE ID and manifest or encrypted PPID")
	}
	if manifest == "" {
		return c.Fetch(ctx, "sgx", "pckcerts", url.Values{"encrypted_ppid": {encPPID}, "pceid": {pceID}})
	}
	u, err := c.endpointURL("sgx", "pckcerts", nil)
	if err != nil {
		return Response{}, err
	}
	body, err := json.Marshal(struct {
		PlatformManifest string `json:"platformManifest"`
		PCEID            string `json:"pceid"`
	}{manifest, pceID})
	if err != nil {
		return Response{}, errors.New("could not encode PCK certificate request")
	}
	// Requests are issued once, including POSTs; registration is never retried.
	return c.request(ctx, http.MethodPost, u, body, true)
}

// IsAllowedCRLURL recognizes the Intel root and intermediate CRL destinations
// used by the original PCCS service, while rejecting userinfo and fragments.
func IsAllowedCRLURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" || u.Host != u.Hostname() || u.Opaque != "" {
		return false
	}
	if u.EscapedPath() != u.Path {
		return false
	}
	if rootHostPattern.MatchString(u.Host) && rootPathPattern.MatchString(u.Path) {
		return true
	}
	return intermediateHostPattern.MatchString(u.Host) && intermediatePathPattern.MatchString(u.Path) && (u.RawQuery != "" || u.ForceQuery)
}

// FetchCRL downloads a CRL without including PCS subscription credentials.
func (c *Client) FetchCRL(ctx context.Context, rawURL string) (Response, error) {
	if !IsAllowedCRLURL(rawURL) {
		return Response{}, errors.New("CRL URL is not an allowed Intel destination")
	}
	u, _ := url.Parse(rawURL)
	return c.request(ctx, http.MethodGet, u, nil, false)
}

func (c *Client) endpointURL(product, endpoint string, query url.Values) (*url.URL, error) {
	if product != "sgx" && product != "tdx" {
		return nil, errors.New("PCS product must be sgx or tdx")
	}
	if !endpointPattern.MatchString(endpoint) {
		return nil, errors.New("invalid relative PCS endpoint")
	}
	u := *c.baseURL
	if strings.Contains(u.Path, "/sgx/") {
		u.Path = strings.Replace(u.Path, "/sgx/", "/"+product+"/", 1)
	} else if strings.Contains(u.Path, "/tdx/") {
		u.Path = strings.Replace(u.Path, "/tdx/", "/"+product+"/", 1)
	} else if product == "tdx" {
		return nil, errors.New("PCS base URL requires a product path for TDX")
	}
	u.Path += endpoint
	u.RawQuery = query.Encode()
	return &u, nil
}

func (c *Client) request(ctx context.Context, method string, u *url.URL, body []byte, authenticated bool) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return Response{}, ErrRequestFailed
	}
	if authenticated && c.apiKey != "" {
		req.Header.Set(subscriptionKeyHeader, c.apiKey)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		// net/url.Error includes the URL, which can contain encrypted PPIDs.
		return Response{}, ErrRequestFailed
	}
	defer res.Body.Close()
	result := Response{StatusCode: res.StatusCode, Header: res.Header.Clone()}
	if res.ContentLength > c.maxResponseBytes {
		return result, ErrResponseTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, c.maxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, ErrResponseRead
	}
	if int64(len(data)) > c.maxResponseBytes {
		return result, ErrResponseTooLarge
	}
	result.Body = data
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return result, &StatusError{StatusCode: res.StatusCode}
	}
	return result, nil
}
