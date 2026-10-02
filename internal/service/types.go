// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2011-2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

// Package service implements the PCCS cache and collateral policy.
package service

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/toratako/pccs-go/internal/collateral"
	"github.com/toratako/pccs-go/internal/pcs"
	"github.com/toratako/pccs-go/internal/store"
)

type Config struct {
	Mode string
	// Roots pins collateral signers. When nil, the chain root is trusted only
	// because the source is authenticated PCS HTTPS or an authenticated import.
	Roots *x509.CertPool
}

type Upstream interface {
	Fetch(context.Context, string, string, url.Values) (pcs.Response, error)
	FetchPCKCertificates(context.Context, string, string, string) (pcs.Response, error)
	FetchCRL(context.Context, string) (pcs.Response, error)
}

type Response struct {
	Body   []byte
	Header http.Header
}

type Platform struct {
	QEID             string `json:"qe_id"`
	PCEID            string `json:"pce_id"`
	CPUSVN           string `json:"cpu_svn"`
	PCESVN           string `json:"pce_svn"`
	EncPPID          string `json:"enc_ppid"`
	PlatformManifest string `json:"platform_manifest"`
	FMSPC            string `json:"fmspc,omitempty"`
	CA               string `json:"ca,omitempty"`
}

type StatusError struct {
	StatusCode int
	Message    string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("PCCS status %d: %s", e.StatusCode, e.Message)
}

func statusError(code int) error {
	messages := map[int]string{400: "Invalid request parameters.", 404: "No cache data for this platform.", 460: "The integrity of the data can't be verified.", 461: "The platform was not found in the cache.", 462: "Certificates are not available for certain TCBs.", 500: "Internal server error occurred.", 502: "Unable to retrieve the collateral from the Intel SGX PCS.", 503: "Server is currently unable to process the request."}
	return &StatusError{StatusCode: code, Message: messages[code]}
}

type Service struct {
	cfg      Config
	db       *store.Store
	upstream Upstream
	mu       sync.Mutex
}

const (
	platformBucket      = "platforms"
	collateralBucket    = "collateral"
	registrationBucket  = "registrations"
	pckChainHeader      = "SGX-PCK-Certificate-Issuer-Chain"
	pckCRLChainHeader   = "SGX-PCK-CRL-Issuer-Chain"
	tcbChainHeader      = "TCB-Info-Issuer-Chain"
	identityChainHeader = "SGX-Enclave-Identity-Issuer-Chain"
)

type platformRecord struct {
	Platform       Platform
	Certificates   []collateral.PCKCertificate
	IssuerChain    string
	Unavailable    []string
	RawTCBs        []Platform
	TCBInfos       []cacheEntry `json:"-"`
	MissingTCBKeys []string     `json:"-"`
}

type cacheEntry struct {
	Product  string
	Endpoint string
	Query    url.Values
	Response Response
}
