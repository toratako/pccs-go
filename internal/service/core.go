// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2011-2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/toratako/pccs-go/internal/collateral"
	"github.com/toratako/pccs-go/internal/pcs"
	"github.com/toratako/pccs-go/internal/store"
)

func New(cfg Config, db *store.Store, upstream Upstream) (*Service, error) {
	cfg.Mode = strings.ToUpper(cfg.Mode)
	if cfg.Mode == "" {
		cfg.Mode = "LAZY"
	}
	if cfg.Mode != "LAZY" && cfg.Mode != "REQ" && cfg.Mode != "OFFLINE" {
		return nil, errors.New("caching mode must be LAZY, REQ, or OFFLINE")
	}
	if db == nil {
		return nil, errors.New("cache store is required")
	}
	if cfg.Mode != "OFFLINE" && upstream == nil {
		return nil, errors.New("upstream is required for online caching modes")
	}
	if cfg.Roots != nil && len(cfg.Roots.Subjects()) == 0 {
		return nil, errors.New("collateral roots must not be empty")
	}
	s := &Service{cfg: cfg, db: db, upstream: upstream}
	if cfg.Roots != nil {
		if err := s.validatePinnedCache(); err != nil {
			return nil, errors.New("cached collateral failed configured trust or validity checks; restore trusted fresh collateral or use a separate data directory")
		}
	}
	return s, nil
}

func (s *Service) Check() error { return s.db.Check() }

// Get serves a cache hit in every mode. Only LAZY fills a public cache miss.
func (s *Service) Get(ctx context.Context, product, endpoint string, query url.Values) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if product != "sgx" && product != "tdx" {
		return Response{}, statusError(400)
	}
	q := canonicalQuery(endpoint, query)
	var p Platform
	if endpoint == "pckcert" {
		p = Platform{QEID: strings.ToUpper(query.Get("qeid")), PCEID: strings.ToUpper(query.Get("pceid")), CPUSVN: strings.ToUpper(query.Get("cpusvn")), PCESVN: strings.ToUpper(query.Get("pcesvn")), EncPPID: strings.ToUpper(query.Get("encrypted_ppid"))}
		if p.QEID == "" || !hexLength(p.PCEID, 2) || !hexLength(p.CPUSVN, 16) || !hexLength(p.PCESVN, 2) {
			return Response{}, statusError(400)
		}
		if response, hit, err := s.knownPlatformResponse(p); err != nil || hit {
			return response, err
		}
	} else {
		if err := validateQuery(endpoint, q); err != nil {
			return Response{}, err
		}
		if response, hit, err := s.readCollateral(product, endpoint, q); err != nil {
			return Response{}, err
		} else if hit {
			return encodeResponse(endpoint, query, response), nil
		}
	}
	// Refreshes and cache fills serialize writes, while existing collateral
	// remains readable through the store's consistent snapshots.
	if err := s.lockMutation(ctx); err != nil {
		return Response{}, err
	}
	defer s.mu.Unlock()
	if endpoint == "pckcert" {
		var record platformRecord
		var found bool
		err := s.db.View(func(tx *store.Tx) error {
			var err error
			found, err = tx.Get(platformBucket, platformKey(p.QEID, p.PCEID), &record)
			return err
		})
		if err != nil {
			return Response{}, err
		}
		if !found {
			if s.cfg.Mode != "LAZY" {
				return Response{}, statusError(461)
			}
			return s.fetchPlatform(ctx, p)
		}
		response, err := s.selectPlatform(record, p)
		if err != nil {
			return Response{}, err
		}
		if len(record.Unavailable) == 0 || s.cfg.Mode != "LAZY" {
			if appendRawTCB(&record, p) {
				if err := s.db.Update(func(tx *store.Tx) error { return putPlatform(tx, &record) }); err != nil {
					return Response{}, err
				}
			}
		}
		return response, nil
	}
	response, found, err := s.readCollateral(product, endpoint, q)
	if err != nil {
		return Response{}, err
	}
	if !found {
		if s.cfg.Mode != "LAZY" {
			return Response{}, statusError(404)
		}
		response, err = s.fetchAndCache(ctx, product, endpoint, q)
		if err != nil {
			return Response{}, err
		}
	}
	return encodeResponse(endpoint, query, response), nil
}

func (s *Service) lockMutation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.mu.TryLock() {
		return nil
	}
	// Mutex has no cancellable wait. A short retry interval avoids leaving
	// goroutines queued behind a long upstream request after cancellation.
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := ctx.Err(); err != nil {
				return err
			}
			if s.mu.TryLock() {
				return nil
			}
		}
	}
}

func (s *Service) knownPlatformResponse(p Platform) (Response, bool, error) {
	var record platformRecord
	known := false
	err := s.db.View(func(tx *store.Tx) error {
		found, err := tx.Get(platformBucket, platformKey(p.QEID, p.PCEID), &record)
		if err != nil || !found {
			return err
		}
		for _, raw := range record.RawTCBs {
			if strings.EqualFold(raw.CPUSVN, p.CPUSVN) && strings.EqualFold(raw.PCESVN, p.PCESVN) {
				known = true
				break
			}
		}
		if !known {
			return nil
		}
		for _, update := range []string{"early", "standard"} {
			var entry cacheEntry
			found, err := tx.Get(collateralBucket, collateralKey("sgx", "tcb", url.Values{"fmspc": {record.Platform.FMSPC}, "update": {update}}), &entry)
			if err != nil {
				return err
			}
			if found {
				record.TCBInfos = append(record.TCBInfos, entry)
			}
		}
		return nil
	})
	if err != nil {
		return Response{}, false, err
	}
	if !known || len(record.TCBInfos) == 0 {
		return Response{}, false, nil
	}
	response, err := s.selectPlatform(record, p)
	return response, true, err
}

func platformKey(qeid, pceid string) string {
	return strings.ToUpper(qeid) + "/" + strings.ToUpper(pceid)
}

func canonicalQuery(endpoint string, q url.Values) url.Values {
	result := url.Values{}
	switch endpoint {
	case "tcb":
		result.Set("fmspc", strings.ToUpper(q.Get("fmspc")))
		fallthrough
	case "qe/identity", "qve/identity":
		update := strings.ToLower(q.Get("update"))
		if update == "" {
			update = "standard"
		}
		result.Set("update", update)
	case "pckcrl":
		result.Set("ca", strings.ToLower(q.Get("ca")))
	case "crl":
		result.Set("uri", q.Get("uri"))
	}
	return result
}

func collateralKey(product, endpoint string, q url.Values) string {
	return product + "/" + endpoint + "?" + canonicalQuery(endpoint, q).Encode()
}

func validateQuery(endpoint string, q url.Values) error {
	switch endpoint {
	case "tcb":
		if !hexLength(q.Get("fmspc"), 6) {
			return statusError(400)
		}
		fallthrough
	case "qe/identity", "qve/identity":
		if q.Get("update") != "standard" && q.Get("update") != "early" {
			return statusError(400)
		}
	case "pckcrl":
		if q.Get("ca") != "processor" && q.Get("ca") != "platform" {
			return statusError(400)
		}
	case "crl":
		if !pcs.IsAllowedCRLURL(q.Get("uri")) {
			return statusError(400)
		}
	case "rootcacrl":
	default:
		return statusError(400)
	}
	return nil
}

func hexLength(value string, n int) bool {
	if len(value) != n*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (s *Service) readCollateral(product, endpoint string, q url.Values) (Response, bool, error) {
	var entry cacheEntry
	var found bool
	err := s.db.View(func(tx *store.Tx) error {
		var err error
		found, err = tx.Get(collateralBucket, collateralKey(product, endpoint, q), &entry)
		return err
	})
	return entry.Response, found, err
}

func putCollateral(tx *store.Tx, product, endpoint string, q url.Values, response Response) error {
	q = canonicalQuery(endpoint, q)
	return tx.Put(collateralBucket, collateralKey(product, endpoint, q), cacheEntry{product, endpoint, q, response})
}

func putPlatform(tx *store.Tx, record *platformRecord) error {
	if err := tx.Put(platformBucket, platformKey(record.Platform.QEID, record.Platform.PCEID), record); err != nil {
		return err
	}
	for _, entry := range record.TCBInfos {
		if err := putCollateral(tx, entry.Product, entry.Endpoint, entry.Query, entry.Response); err != nil {
			return err
		}
	}
	for _, key := range record.MissingTCBKeys {
		if err := tx.Delete(collateralBucket, key); err != nil {
			return err
		}
	}
	return nil
}

func upstreamResponse(result pcs.Response, err error) (Response, error) {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Response{}, err
		}
		var status *pcs.StatusError
		if errors.As(err, &status) {
			if status.StatusCode == 404 || status.StatusCode == 461 || status.StatusCode == 462 {
				return Response{}, statusError(404)
			}
		}
		return Response{}, statusError(502)
	}
	if result.StatusCode != http.StatusOK {
		if result.StatusCode == 404 || result.StatusCode == 461 || result.StatusCode == 462 {
			return Response{}, statusError(404)
		}
		return Response{}, statusError(502)
	}
	header := result.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	return Response{Body: bytes.Clone(result.Body), Header: header}, nil
}

func (s *Service) fetchAndCache(ctx context.Context, product, endpoint string, q url.Values) (Response, error) {
	response, err := s.stageCollateral(ctx, product, endpoint, q)
	if err != nil {
		return Response{}, err
	}
	err = s.db.Update(func(tx *store.Tx) error { return putCollateral(tx, product, endpoint, q, response) })
	return response, err
}

func (s *Service) stageCollateral(ctx context.Context, product, endpoint string, q url.Values) (Response, error) {
	if s.upstream == nil {
		return Response{}, statusError(503)
	}
	q = canonicalQuery(endpoint, q)
	var response Response
	var err error
	switch endpoint {
	case "crl":
		response, err = upstreamResponse(s.upstream.FetchCRL(ctx, q.Get("uri")))
	case "rootcacrl":
		chain, chainErr := s.rootChain(ctx)
		if chainErr != nil {
			return Response{}, chainErr
		}
		certs, parseErr := collateral.ParseCertificates([]byte(chain))
		if parseErr != nil || len(certs) == 0 {
			return Response{}, statusError(460)
		}
		root := certs[len(certs)-1]
		if len(root.CRLDistributionPoints) == 0 || !pcs.IsAllowedCRLURL(root.CRLDistributionPoints[0]) {
			return Response{}, statusError(460)
		}
		response, err = upstreamResponse(s.upstream.FetchCRL(ctx, root.CRLDistributionPoints[0]))
		if err == nil {
			response.Header.Set(pckCRLChainHeader, chain)
		}
	default:
		fetchQ := make(url.Values, len(q))
		for key, values := range q {
			fetchQ[key] = append([]string(nil), values...)
		}
		if endpoint == "pckcrl" {
			fetchQ.Set("encoding", "der")
		}
		response, err = upstreamResponse(s.upstream.Fetch(ctx, product, endpoint, fetchQ))
	}
	if err != nil {
		return Response{}, err
	}
	return s.validateCollateral(product, endpoint, q, response)
}

func (s *Service) rootChain(ctx context.Context) (string, error) {
	var chain string
	err := s.db.View(func(tx *store.Tx) error {
		for _, key := range tx.Keys(collateralBucket) {
			var entry cacheEntry
			if _, err := tx.Get(collateralBucket, key, &entry); err != nil {
				return err
			}
			for _, header := range []string{identityChainHeader, tcbChainHeader, pckCRLChainHeader} {
				if value := entry.Response.Header.Get(header); value != "" {
					chain = value
					return nil
				}
			}
		}
		for _, key := range tx.Keys(platformBucket) {
			var record platformRecord
			if _, err := tx.Get(platformBucket, key, &record); err != nil {
				return err
			}
			if record.IssuerChain != "" {
				chain = record.IssuerChain
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if chain != "" {
		return chain, nil
	}
	response, err := s.fetchAndCache(ctx, "sgx", "qe/identity", url.Values{"update": {"standard"}})
	if err != nil {
		return "", err
	}
	return response.Header.Get(identityChainHeader), nil
}

func (s *Service) rootsFor(chain []byte) (*x509.CertPool, error) {
	if s.cfg.Roots != nil {
		return s.cfg.Roots, nil
	}
	certs, err := collateral.ParseCertificates(chain)
	if err != nil || len(certs) == 0 {
		return nil, statusError(460)
	}
	root := certs[len(certs)-1]
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, statusError(460)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return roots, nil
}

func (s *Service) validateCollateral(product, endpoint string, q url.Values, response Response) (Response, error) {
	if response.Header == nil {
		response.Header = make(http.Header)
	}
	now := time.Now()
	if endpoint == "tcb" || endpoint == "qe/identity" || endpoint == "qve/identity" {
		field, header := "enclaveIdentity", identityChainHeader
		if endpoint == "tcb" {
			field, header = "tcbInfo", tcbChainHeader
			if response.Header.Get(header) == "" {
				response.Header.Set(header, response.Header.Get("SGX-TCB-Info-Issuer-Chain"))
			}
		}
		chain := []byte(response.Header.Get(header))
		roots, err := s.rootsFor(chain)
		if err != nil {
			return Response{}, statusError(460)
		}
		payload, err := collateral.VerifySignedJSON(response.Body, field, chain, roots, now)
		if err != nil {
			return Response{}, statusError(460)
		}
		if err = collateral.VerifyFreshness(payload, now); err != nil {
			return Response{}, statusError(460)
		}
		var metadata struct {
			FMSPC string `json:"fmspc"`
			ID    string `json:"id"`
		}
		if json.Unmarshal(payload, &metadata) != nil {
			return Response{}, statusError(460)
		}
		if endpoint == "tcb" {
			if !strings.EqualFold(metadata.FMSPC, q.Get("fmspc")) || !strings.EqualFold(metadata.ID, product) {
				return Response{}, statusError(460)
			}
			if product == "sgx" {
				if _, err := collateral.ParseTCBInfo(payload); err != nil {
					return Response{}, statusError(460)
				}
			}
		} else {
			id := "QE"
			if endpoint == "qve/identity" {
				id = "QVE"
			} else if product == "tdx" {
				id = "TD_QE"
			}
			if !strings.EqualFold(metadata.ID, id) {
				return Response{}, statusError(460)
			}
		}
		response.Header.Set("Content-Type", "application/json")
	} else {
		crl, err := collateral.ParseCRL(response.Body)
		if err != nil {
			return Response{}, statusError(460)
		}
		chain := []byte(response.Header.Get(pckCRLChainHeader))
		if endpoint == "rootcacrl" && len(chain) == 0 {
			chain = []byte(response.Header.Get(pckChainHeader))
		}
		if endpoint == "crl" && len(chain) == 0 {
			chain, err = s.cachedCRLChain(crl)
			if err != nil {
				return Response{}, err
			}
		}
		if len(chain) > 0 {
			certs, err := collateral.ParseCertificates(chain)
			if err != nil {
				return Response{}, statusError(460)
			}
			issuer := certs[0]
			if endpoint == "rootcacrl" {
				issuer = certs[len(certs)-1]
			}
			if endpoint == "crl" {
				for _, candidate := range certs {
					if bytes.Equal(candidate.RawSubject, crl.RawIssuer) {
						issuer = candidate
						break
					}
				}
			}
			roots, err := s.rootsFor(chain)
			if err != nil {
				return Response{}, statusError(460)
			}
			if collateral.VerifyCertificateChain(issuer, chain, roots, now) != nil || collateral.VerifyCRL(crl, issuer, now) != nil {
				return Response{}, statusError(460)
			}
			if endpoint == "pckcrl" && !strings.Contains(strings.ToLower(issuer.Subject.CommonName), q.Get("ca")) {
				return Response{}, statusError(460)
			}
		} else if endpoint != "crl" || s.cfg.Roots != nil {
			return Response{}, statusError(460)
		}
		// A direct allowlisted Intel CRL download may precede issuer caching.
		// HTTPS authenticates that source; still reject malformed/stale CRLs.
		if crl.ThisUpdate.IsZero() || !crl.NextUpdate.After(crl.ThisUpdate) || now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
			return Response{}, statusError(460)
		}
		response.Body = bytes.Clone(crl.Raw)
		response.Header.Set("Content-Type", "application/pkix-crl")
	}
	return response, nil
}

func (s *Service) cachedCRLChain(crl *x509.RevocationList) ([]byte, error) {
	var result []byte
	try := func(chain string) bool {
		certs, err := collateral.ParseCertificates([]byte(chain))
		if err != nil {
			return false
		}
		for _, cert := range certs {
			if bytes.Equal(cert.RawSubject, crl.RawIssuer) && crl.CheckSignatureFrom(cert) == nil {
				result = []byte(chain)
				return true
			}
		}
		return false
	}
	err := s.db.View(func(tx *store.Tx) error {
		for _, key := range tx.Keys(collateralBucket) {
			var entry cacheEntry
			if _, err := tx.Get(collateralBucket, key, &entry); err != nil {
				return err
			}
			for _, header := range []string{pckCRLChainHeader, pckChainHeader, tcbChainHeader, identityChainHeader} {
				if try(entry.Response.Header.Get(header)) {
					return nil
				}
			}
		}
		for _, key := range tx.Keys(platformBucket) {
			var record platformRecord
			if _, err := tx.Get(platformBucket, key, &record); err != nil {
				return err
			}
			if try(record.IssuerChain) {
				return nil
			}
		}
		return nil
	})
	return result, err
}

func encodeResponse(endpoint string, q url.Values, response Response) Response {
	response.Body = bytes.Clone(response.Body)
	response.Header = response.Header.Clone()
	if endpoint == "rootcacrl" || (endpoint == "pckcrl" && !strings.EqualFold(q.Get("encoding"), "der")) {
		response.Body = []byte(hex.EncodeToString(response.Body))
		response.Header.Set("Content-Type", "application/x-pem-file")
	}
	if endpoint == "rootcacrl" {
		response.Header.Del(pckCRLChainHeader)
		response.Header.Del(pckChainHeader)
		response.Header.Set("Content-Type", "application/pkix-crl")
	}
	return response
}

func appendRawTCB(record *platformRecord, p Platform) bool {
	if p.CPUSVN == "" || p.PCESVN == "" {
		return false
	}
	for _, raw := range record.RawTCBs {
		if strings.EqualFold(raw.CPUSVN, p.CPUSVN) && strings.EqualFold(raw.PCESVN, p.PCESVN) {
			return false
		}
	}
	record.RawTCBs = append(record.RawTCBs, p)
	return true
}

func (s *Service) stagePlatform(ctx context.Context, p Platform) (platformRecord, error) {
	var record platformRecord
	p.QEID, p.PCEID = strings.ToUpper(p.QEID), strings.ToUpper(p.PCEID)
	p.CPUSVN, p.PCESVN = strings.ToUpper(p.CPUSVN), strings.ToUpper(p.PCESVN)
	if p.QEID == "" || !hexLength(p.PCEID, 2) || (p.PlatformManifest == "" && p.EncPPID == "") {
		return record, statusError(400)
	}
	if p.PlatformManifest == "" && strings.Trim(p.EncPPID, "0") == "" {
		return record, statusError(404)
	}
	if s.upstream == nil {
		return record, statusError(503)
	}
	if err := s.db.View(func(tx *store.Tx) error {
		_, err := tx.Get(platformBucket, platformKey(p.QEID, p.PCEID), &record)
		return err
	}); err != nil {
		return record, err
	}
	response, err := upstreamResponse(s.upstream.FetchPCKCertificates(ctx, p.EncPPID, p.PCEID, p.PlatformManifest))
	if err != nil {
		return record, err
	}
	var wire []struct {
		TCBM string `json:"tcbm"`
		Cert string `json:"cert"`
	}
	if json.Unmarshal(response.Body, &wire) != nil {
		return record, statusError(460)
	}
	record.Platform = p
	record.Certificates = nil
	record.Unavailable = nil
	record.TCBInfos = nil
	record.MissingTCBKeys = nil
	record.Platform.FMSPC = strings.ToUpper(response.Header.Get("SGX-FMSPC"))
	record.Platform.CA = strings.ToUpper(response.Header.Get("SGX-PCK-Certificate-CA-Type"))
	record.IssuerChain = response.Header.Get(pckChainHeader)
	for _, entry := range wire {
		cert, err := url.PathUnescape(entry.Cert)
		if err != nil {
			return record, statusError(460)
		}
		tcbm := strings.ToUpper(entry.TCBM)
		if !hexLength(tcbm, 18) {
			return record, statusError(460)
		}
		if cert == "Not available" {
			record.Unavailable = append(record.Unavailable, tcbm)
			continue
		}
		record.Certificates = append(record.Certificates, collateral.PCKCertificate{TCBM: tcbm, Cert: cert})
	}
	if len(record.Certificates) == 0 {
		return record, statusError(404)
	}
	if err := s.validatePlatformRecord(&record); err != nil {
		return record, err
	}
	for _, product := range []string{"sgx", "tdx"} {
		for _, update := range []string{"early", "standard"} {
			q := url.Values{"fmspc": {record.Platform.FMSPC}, "update": {update}}
			tcb, err := s.stageCollateral(ctx, product, "tcb", q)
			if err != nil {
				var status *StatusError
				if errors.As(err, &status) && status.StatusCode == 404 && (product == "tdx" || update == "early") {
					record.MissingTCBKeys = append(record.MissingTCBKeys, collateralKey(product, "tcb", q))
					continue
				}
				return record, err
			}
			if product == "sgx" {
				info, err := collateral.ParseTCBInfo(tcb.Body)
				if err != nil || !strings.EqualFold(info.PCEID, p.PCEID) {
					return record, statusError(460)
				}
			}
			if !sameChainRoot(record.IssuerChain, tcb.Header.Get(tcbChainHeader)) {
				return record, statusError(460)
			}
			record.TCBInfos = append(record.TCBInfos, cacheEntry{product, "tcb", q, tcb})
		}
	}
	if len(record.Unavailable) == 0 || s.cfg.Mode != "LAZY" {
		appendRawTCB(&record, p)
	}
	for _, raw := range record.RawTCBs {
		if _, err := s.selectPlatform(record, raw); err != nil {
			return record, err
		}
	}
	return record, nil
}

func (s *Service) validatePlatformRecord(record *platformRecord) error {
	p := record.Platform
	if !hexLength(p.FMSPC, 6) || !hexLength(p.PCEID, 2) || (p.CA != "PROCESSOR" && p.CA != "PLATFORM") || len(record.Certificates) == 0 {
		return statusError(460)
	}
	chain := []byte(record.IssuerChain)
	roots, err := s.rootsFor(chain)
	if err != nil {
		return statusError(460)
	}
	seen := map[string]bool{}
	ppid := ""
	for _, cert := range record.Certificates {
		info, err := collateral.ParsePCKCertificate([]byte(cert.Cert))
		if err != nil {
			return statusError(460)
		}
		if seen[cert.TCBM] || !strings.EqualFold(cert.TCBM, info.TCB.TCBM()) || !strings.EqualFold(info.FMSPC, p.FMSPC) || !strings.EqualFold(info.PCEID, p.PCEID) || info.CA != p.CA {
			return statusError(460)
		}
		if ppid != "" && ppid != info.PPID {
			return statusError(460)
		}
		ppid = info.PPID
		seen[cert.TCBM] = true
		if collateral.VerifyCertificateChain(info.Certificate, chain, roots, time.Now()) != nil {
			return statusError(460)
		}
	}
	return nil
}

func (s *Service) selectPlatform(record platformRecord, p Platform) (Response, error) {
	var tcb Response
	found := false
	for _, update := range []string{"early", "standard"} {
		for _, entry := range record.TCBInfos {
			if entry.Product == "sgx" && entry.Endpoint == "tcb" && strings.EqualFold(entry.Query.Get("update"), update) {
				tcb = entry.Response
				found = true
				break
			}
		}
		if found {
			break
		}
		if len(record.TCBInfos) > 0 {
			continue
		}
		var err error
		tcb, found, err = s.readCollateral("sgx", "tcb", url.Values{"fmspc": {record.Platform.FMSPC}, "update": {update}})
		if err != nil {
			return Response{}, err
		}
		if found {
			break
		}
	}
	if !found {
		return Response{}, statusError(404)
	}
	info, err := collateral.ParseTCBInfo(tcb.Body)
	if err != nil || !strings.EqualFold(info.PCEID, record.Platform.PCEID) || !strings.EqualFold(info.FMSPC, record.Platform.FMSPC) {
		return Response{}, statusError(460)
	}
	selected, err := collateral.SelectBestPCKCert(p.CPUSVN, p.PCESVN, p.PCEID, record.Certificates, tcb.Body)
	if err != nil {
		return Response{}, statusError(404)
	}
	header := make(http.Header)
	header.Set("SGX-TCBm", selected.TCBM)
	header.Set("SGX-FMSPC", record.Platform.FMSPC)
	header.Set("SGX-PCK-Certificate-CA-Type", record.Platform.CA)
	header.Set(pckChainHeader, record.IssuerChain)
	header.Set("Content-Type", "application/x-pem-file")
	return Response{Body: []byte(selected.Cert), Header: header}, nil
}

func (s *Service) fetchPlatform(ctx context.Context, p Platform) (Response, error) {
	record, err := s.stagePlatform(ctx, p)
	if err != nil {
		var status *StatusError
		if s.cfg.Mode == "REQ" && errors.As(err, &status) && status.StatusCode == 404 && len(record.Unavailable) > 0 {
			if queueErr := s.db.Update(func(tx *store.Tx) error { return queueUnavailable(tx, &record) }); queueErr != nil {
				return Response{}, queueErr
			}
		}
		return Response{}, err
	}
	var response Response
	if p.CPUSVN != "" && p.PCESVN != "" {
		response, err = s.selectPlatform(record, p)
		if err != nil {
			return Response{}, err
		}
	}
	if err = s.db.Update(func(tx *store.Tx) error {
		if err := putPlatform(tx, &record); err != nil {
			return err
		}
		if s.cfg.Mode == "REQ" {
			return queueUnavailable(tx, &record)
		}
		return nil
	}); err != nil {
		return Response{}, err
	}
	return response, nil
}

func queueUnavailable(tx *store.Tx, record *platformRecord) error {
	for _, tcbm := range record.Unavailable {
		if !hexLength(tcbm, 18) {
			return statusError(460)
		}
		raw := record.Platform
		raw.CPUSVN, raw.PCESVN = tcbm[:32], tcbm[32:]
		if err := tx.Put(registrationBucket, registrationKey(raw), registrationRecord{raw, "reg_na"}); err != nil {
			return err
		}
	}
	return nil
}

func sameChainRoot(first, second string) bool {
	a, err := collateral.ParseCertificates([]byte(first))
	if err != nil || len(a) == 0 {
		return false
	}
	b, err := collateral.ParseCertificates([]byte(second))
	if err != nil || len(b) == 0 {
		return false
	}
	return bytes.Equal(a[len(a)-1].Raw, b[len(b)-1].Raw)
}
