// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2011-2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package service

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/toratako/pccs-go/internal/collateral"
	"github.com/toratako/pccs-go/internal/pcs"
	"github.com/toratako/pccs-go/internal/store"
)

const policyBucket = "policies"

type registrationRecord struct {
	Platform Platform `json:"platform"`
	State    string   `json:"state"`
}

func registrationKey(p Platform) string {
	data, _ := json.Marshal([]string{p.QEID, p.PCEID, p.CPUSVN, p.PCESVN, p.PlatformManifest})
	digest := sha512.Sum384(data)
	return hex.EncodeToString(digest[:])
}

func normalizePlatform(p Platform, registration bool) (Platform, error) {
	if len(p.QEID) < 1 || len(p.QEID) > 260 || !hexLength(p.PCEID, 2) {
		return p, statusError(400)
	}
	if p.CPUSVN != "" && !hexLength(p.CPUSVN, 16) || p.PCESVN != "" && !hexLength(p.PCESVN, 2) || p.EncPPID != "" && !hexLength(p.EncPPID, 384) {
		return p, statusError(400)
	}
	if (p.CPUSVN == "") != (p.PCESVN == "") {
		return p, statusError(400)
	}
	if registration {
		if p.PlatformManifest != "" {
			p.CPUSVN, p.PCESVN, p.EncPPID = "", "", ""
		} else if p.CPUSVN == "" || p.EncPPID == "" {
			return p, statusError(400)
		}
	}
	p.QEID, p.PCEID = strings.ToUpper(p.QEID), strings.ToUpper(p.PCEID)
	p.CPUSVN, p.PCESVN = strings.ToUpper(p.CPUSVN), strings.ToUpper(p.PCESVN)
	p.FMSPC, p.CA = strings.ToUpper(p.FMSPC), strings.ToUpper(p.CA)
	return p, nil
}

// Register queues platforms offline and retrieves missing collateral online.
// REQ registrations remain in the queue if provisioning fails.
func (s *Service) Register(ctx context.Context, p Platform, update string) error {
	update = strings.ToLower(update)
	if update == "" {
		update = "standard"
	}
	if update != "standard" && update != "early" && update != "all" {
		return statusError(400)
	}
	p, err := normalizePlatform(p, true)
	if err != nil {
		return err
	}
	if err := s.lockMutation(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	var cached platformRecord
	var found bool
	err = s.db.View(func(tx *store.Tx) error {
		var e error
		found, e = tx.Get(platformBucket, platformKey(p.QEID, p.PCEID), &cached)
		return e
	})
	if err != nil {
		return err
	}
	isCached := false
	if found {
		if p.PlatformManifest == "" {
			p.PlatformManifest = cached.Platform.PlatformManifest
			for _, raw := range cached.RawTCBs {
				if raw.CPUSVN == p.CPUSVN && raw.PCESVN == p.PCESVN {
					_, err = s.selectPlatform(cached, p)
					isCached = err == nil
					break
				}
			}
			if !isCached && s.cfg.Mode != "OFFLINE" {
				if _, err = s.selectPlatform(cached, p); err == nil {
					appendRawTCB(&cached, p)
					if err := s.db.Update(func(tx *store.Tx) error { return putPlatform(tx, &cached) }); err != nil {
						return err
					}
					isCached = true
				}
			}
		} else {
			isCached = p.PlatformManifest == cached.Platform.PlatformManifest
		}
	}
	queue := func(state string) error {
		return s.db.Update(func(tx *store.Tx) error {
			return tx.Put(registrationBucket, registrationKey(p), registrationRecord{p, state})
		})
	}
	if s.cfg.Mode == "OFFLINE" {
		if !isCached {
			return queue("reg")
		}
		return nil
	}
	if !isCached {
		if s.cfg.Mode == "REQ" {
			if err := queue("reg"); err != nil {
				return err
			}
		}
		if _, err = s.fetchPlatform(ctx, p); err != nil {
			return err
		}
		if s.cfg.Mode == "REQ" {
			if err := s.db.Update(func(tx *store.Tx) error { return tx.Delete(registrationBucket, registrationKey(p)) }); err != nil {
				return err
			}
		}
	}
	for _, ca := range []string{"processor", "platform"} {
		q := url.Values{"ca": {ca}}
		if _, ok, err := s.readCollateral("sgx", "pckcrl", q); err != nil {
			return err
		} else if !ok {
			if _, err := s.fetchAndCache(ctx, "sgx", "pckcrl", q); err != nil {
				return err
			}
		}
	}
	updates := []string{update}
	if update == "all" {
		updates = []string{"standard", "early"}
	}
	for _, u := range updates {
		for _, item := range [][2]string{{"sgx", "qe/identity"}, {"sgx", "qve/identity"}, {"tdx", "qe/identity"}} {
			q := url.Values{"update": {u}}
			if _, ok, err := s.readCollateral(item[0], item[1], q); err != nil {
				return err
			} else if !ok {
				if _, err := s.fetchAndCache(ctx, item[0], item[1], q); err != nil {
					return err
				}
			}
		}
	}
	if _, ok, err := s.readCollateral("sgx", "rootcacrl", nil); err != nil {
		return err
	} else if !ok {
		if _, err := s.fetchAndCache(ctx, "sgx", "rootcacrl", nil); err != nil {
			return err
		}
	}
	return nil
}

func parseFMSPCSource(source string) (map[string]bool, error) {
	if len(source) < 2 || source[0] != '[' || source[len(source)-1] != ']' {
		return nil, statusError(400)
	}
	values := strings.TrimSpace(source[1 : len(source)-1])
	out := make(map[string]bool)
	if values == "" {
		return out, nil
	}
	for _, value := range strings.Split(values, ",") {
		if !hexLength(value, 6) {
			return nil, statusError(400)
		}
		out[strings.ToUpper(value)] = true
	}
	return out, nil
}

// Platforms atomically drains a registration queue or lists cached raw TCBs.
func (s *Service) Platforms(ctx context.Context, source string) ([]Platform, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == "" {
		source = "reg"
	}
	result := make([]Platform, 0)
	if source == "reg" || source == "reg_na" {
		err := s.db.Update(func(tx *store.Tx) error {
			for _, key := range tx.Keys(registrationBucket) {
				var record registrationRecord
				if _, err := tx.Get(registrationBucket, key, &record); err != nil {
					return err
				}
				if record.State == source {
					result = append(result, record.Platform)
					if err := tx.Delete(registrationBucket, key); err != nil {
						return err
					}
				}
			}
			return nil
		})
		return result, err
	}
	filter, err := parseFMSPCSource(source)
	if err != nil {
		return nil, err
	}
	err = s.db.View(func(tx *store.Tx) error {
		for _, key := range tx.Keys(platformBucket) {
			var record platformRecord
			if _, err := tx.Get(platformBucket, key, &record); err != nil {
				return err
			}
			if len(filter) > 0 && !filter[record.Platform.FMSPC] {
				continue
			}
			for _, p := range record.RawTCBs {
				p.EncPPID, p.PlatformManifest = record.Platform.EncPPID, record.Platform.PlatformManifest
				p.FMSPC, p.CA = "", ""
				result = append(result, p)
			}
		}
		return nil
	})
	return result, err
}

type policyRecord struct {
	ID        string `json:"id"`
	FMSPC     string `json:"fmspc"`
	IsDefault *bool  `json:"is_default"`
	Policy    string `json:"policy"`
	Type      int    `json:"type"`
}

func policyType(policy string) (int, error) {
	parts := strings.Split(policy, ".")
	if len(parts) < 2 {
		return 0, statusError(400)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, statusError(400)
	}
	var payload struct {
		Payload string `json:"policy_payload"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return 0, statusError(400)
	}
	var policies struct {
		Array []struct {
			Environment struct {
				ClassID string `json:"class_id"`
			} `json:"environment"`
		} `json:"policy_array"`
	}
	if json.Unmarshal([]byte(payload.Payload), &policies) != nil {
		return 0, statusError(400)
	}
	for _, p := range policies.Array {
		switch strings.ToLower(p.Environment.ClassID) {
		case "3123ec35-8d38-4ea5-87a5-d6c48b567570":
			return 0, nil
		case "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f":
			return 1, nil
		case "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3":
			return 2, nil
		case "3769258c-75e6-4bc7-8d72-d2b0e224cad2":
		default:
			return 0, statusError(400)
		}
	}
	return 0, statusError(400)
}

func (s *Service) PutPolicy(ctx context.Context, body []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var p policyRecord
	if decodeImportJSON(body, &p) != nil || p.IsDefault == nil || !hexLength(p.FMSPC, 6) || p.Policy == "" {
		return "", statusError(400)
	}
	typ, err := policyType(p.Policy)
	if err != nil {
		return "", err
	}
	p.Type, p.FMSPC = typ, strings.ToUpper(p.FMSPC)
	digest := sha512.Sum384([]byte(p.Policy))
	p.ID = hex.EncodeToString(digest[:])
	err = s.db.Update(func(tx *store.Tx) error {
		if *p.IsDefault {
			for _, key := range tx.Keys(policyBucket) {
				var old policyRecord
				if _, err := tx.Get(policyBucket, key, &old); err != nil {
					return err
				}
				if old.FMSPC == p.FMSPC && old.IsDefault != nil && *old.IsDefault {
					flag := false
					old.IsDefault = &flag
					if err := tx.Put(policyBucket, key, old); err != nil {
						return err
					}
				}
			}
		}
		return tx.Put(policyBucket, p.ID, p)
	})
	return p.ID, err
}

func (s *Service) Policies(ctx context.Context, fmspc string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !hexLength(fmspc, 6) {
		return "", statusError(400)
	}
	fmspc = strings.ToUpper(fmspc)
	var policies []string
	err := s.db.View(func(tx *store.Tx) error {
		for _, key := range tx.Keys(policyBucket) {
			var p policyRecord
			if _, err := tx.Get(policyBucket, key, &p); err != nil {
				return err
			}
			if p.FMSPC == fmspc && p.IsDefault != nil && *p.IsDefault {
				policies = append(policies, p.Policy)
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(policies) == 0 {
		return "", statusError(404)
	}
	return strings.Join(policies, ","), nil
}

// Refresh stages all requested replacements before one atomic cache update.
func (s *Service) Refresh(ctx context.Context, kind, fmspc string) error {
	if kind != "" && kind != "certs" {
		return statusError(400)
	}
	if s.cfg.Mode == "OFFLINE" {
		return statusError(503)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.lockMutation(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if kind == "certs" {
		var filter map[string]bool
		var err error
		if fmspc != "" && fmspc != "all" {
			if strings.HasPrefix(fmspc, "[") {
				filter, err = parseFMSPCSource(fmspc)
			} else if hexLength(fmspc, 6) {
				filter = map[string]bool{strings.ToUpper(fmspc): true}
			} else {
				err = statusError(400)
			}
			if err != nil {
				return err
			}
		}
		var platforms []Platform
		if err := s.db.View(func(tx *store.Tx) error {
			for _, key := range tx.Keys(platformBucket) {
				var record platformRecord
				if _, err := tx.Get(platformBucket, key, &record); err != nil {
					return err
				}
				if len(filter) == 0 || filter[record.Platform.FMSPC] {
					platforms = append(platforms, record.Platform)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		staged := make([]platformRecord, 0, len(platforms))
		for _, p := range platforms {
			record, err := s.stagePlatform(ctx, p)
			if err != nil {
				return err
			}
			staged = append(staged, record)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return s.db.Update(func(tx *store.Tx) error {
			for i := range staged {
				if err := putPlatform(tx, &staged[i]); err != nil {
					return err
				}
				if s.cfg.Mode == "REQ" {
					if err := queueUnavailable(tx, &staged[i]); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	var existing []cacheEntry
	if err := s.db.View(func(tx *store.Tx) error {
		for _, key := range tx.Keys(collateralBucket) {
			var entry cacheEntry
			if _, err := tx.Get(collateralBucket, key, &entry); err != nil {
				return err
			}
			existing = append(existing, entry)
		}
		return nil
	}); err != nil {
		return err
	}
	staged := map[string]cacheEntry{}
	for _, entry := range existing {
		response, err := s.stageCollateral(ctx, entry.Product, entry.Endpoint, entry.Query)
		if err != nil {
			var status *StatusError
			if (entry.Endpoint == "qe/identity" || entry.Endpoint == "qve/identity") && errors.As(err, &status) && status.StatusCode == 404 {
				staged[collateralKey(entry.Product, entry.Endpoint, entry.Query)] = entry
				continue
			}
			return err
		}
		entry.Response = response
		staged[collateralKey(entry.Product, entry.Endpoint, entry.Query)] = entry
	}
	for _, product := range []string{"sgx", "tdx"} {
		endpoints := []string{"qe/identity"}
		if product == "sgx" {
			endpoints = append(endpoints, "qve/identity")
		}
		for _, endpoint := range endpoints {
			for _, update := range []string{"standard", "early"} {
				q := url.Values{"update": {update}}
				key := collateralKey(product, endpoint, q)
				if _, ok := staged[key]; ok {
					continue
				}
				response, err := s.stageCollateral(ctx, product, endpoint, q)
				if err != nil {
					var status *StatusError
					if errors.As(err, &status) && status.StatusCode == 404 {
						continue
					}
					return err
				}
				staged[key] = cacheEntry{product, endpoint, q, response}
			}
		}
	}
	rootKey := collateralKey("sgx", "rootcacrl", nil)
	if _, ok := staged[rootKey]; !ok {
		var chain string
		for _, entry := range staged {
			for _, header := range []string{identityChainHeader, tcbChainHeader, pckCRLChainHeader} {
				if value := entry.Response.Header.Get(header); value != "" {
					chain = value
					break
				}
			}
			if chain != "" {
				break
			}
		}
		certs, err := collateral.ParseCertificates([]byte(chain))
		if err != nil {
			return statusError(460)
		}
		root := certs[len(certs)-1]
		if len(root.CRLDistributionPoints) == 0 || !pcs.IsAllowedCRLURL(root.CRLDistributionPoints[0]) {
			return statusError(460)
		}
		response, err := upstreamResponse(s.upstream.FetchCRL(ctx, root.CRLDistributionPoints[0]))
		if err != nil {
			return err
		}
		response.Header.Set(pckCRLChainHeader, chain)
		response, err = s.validateCollateral("sgx", "rootcacrl", nil, response)
		if err != nil {
			return err
		}
		staged[rootKey] = cacheEntry{"sgx", "rootcacrl", nil, response}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(func(tx *store.Tx) error {
		for _, entry := range staged {
			if err := putCollateral(tx, entry.Product, entry.Endpoint, entry.Query, entry.Response); err != nil {
				return err
			}
		}
		return nil
	})
}
