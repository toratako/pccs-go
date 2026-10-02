// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2011-2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/toratako/pccs-go/internal/collateral"
	"github.com/toratako/pccs-go/internal/pcs"
	"github.com/toratako/pccs-go/internal/store"
)

type importBundle struct {
	Platforms   []Platform `json:"platforms"`
	Collaterals struct {
		Version  int `json:"version"`
		PCKCerts []struct {
			QEID     string  `json:"qe_id"`
			PCEID    string  `json:"pce_id"`
			EncPPID  *string `json:"enc_ppid"`
			Manifest string  `json:"platform_manifest"`
			Certs    []struct {
				TCBM string          `json:"tcbm"`
				Cert string          `json:"cert"`
				TCB  json.RawMessage `json:"tcb"`
			} `json:"certs"`
		} `json:"pck_certs"`
		TCBInfos []map[string]json.RawMessage `json:"tcbinfos"`
		PCKCRLs  struct {
			Processor string `json:"processorCrl"`
			Platform  string `json:"platformCrl"`
		} `json:"pckcacrl"`
		Certificates      map[string]json.RawMessage `json:"certificates"`
		QEIdentity        string                     `json:"qeidentity"`
		QEIdentityEarly   string                     `json:"qeidentity_early"`
		TDQEIdentity      string                     `json:"tdqeidentity"`
		TDQEIdentityEarly string                     `json:"tdqeidentity_early"`
		QVEIdentity       string                     `json:"qveidentity"`
		QVEIdentityEarly  string                     `json:"qveidentity_early"`
		RootCRL           string                     `json:"rootcacrl"`
		RootCDP           string                     `json:"rootcacrl_cdp"`
	} `json:"collaterals"`
}

// decodeImportJSON rejects duplicate keys at every level and trailing data.
// Unknown fields remain accepted, matching the PCS Client Tool schemas.
func decodeImportJSON(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var consume func() error
	consume = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or invalid JSON key")
				}
				seen[name] = true
				if err := consume(); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := consume(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := consume(); err != nil {
		return statusError(400)
	}
	if _, err := d.Token(); err != io.EOF {
		return statusError(400)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return statusError(400)
	}
	return nil
}

func importChainStrings(certificates map[string]json.RawMessage) (map[string]string, error) {
	chains := map[string]string{}
	if certificates == nil {
		return nil, statusError(400)
	}
	var pck map[string]string
	if value, ok := certificates[pckChainHeader]; !ok || json.Unmarshal(value, &pck) != nil || pck == nil {
		return nil, statusError(400)
	}
	for ca, chain := range pck {
		if ca != "PROCESSOR" && ca != "PLATFORM" || chain == "" {
			return nil, statusError(400)
		}
		chains[ca] = chain
	}
	for _, header := range []string{tcbChainHeader, "SGX-TCB-Info-Issuer-Chain", identityChainHeader} {
		if raw, ok := certificates[header]; ok {
			var chain string
			if json.Unmarshal(raw, &chain) != nil || chain == "" {
				return nil, statusError(400)
			}
			chains[header] = chain
		}
	}
	if chains[tcbChainHeader] == "" {
		chains[tcbChainHeader] = chains["SGX-TCB-Info-Issuer-Chain"]
	}
	return chains, nil
}

// Import validates an entire v4 PCS Client Tool bundle before committing it.
// With no pinned roots, the authenticated administrator supplies the root;
// every chain in the upload must still have the same valid self-signed root.
func (s *Service) Import(ctx context.Context, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var bundle importBundle
	if err := decodeImportJSON(body, &bundle); err != nil {
		return err
	}
	if bundle.Platforms == nil || bundle.Collaterals.Version != 4 || bundle.Collaterals.PCKCerts == nil || bundle.Collaterals.TCBInfos == nil {
		return statusError(400)
	}
	chains, err := importChainStrings(bundle.Collaterals.Certificates)
	if err != nil {
		return err
	}
	var root *x509.Certificate
	for _, chain := range chains {
		if chain == "" {
			continue
		}
		certs, err := collateral.ParseCertificates([]byte(chain))
		if err != nil {
			return statusError(460)
		}
		last := certs[len(certs)-1]
		if !last.IsCA || last.CheckSignatureFrom(last) != nil {
			return statusError(460)
		}
		if root != nil && !bytes.Equal(root.Raw, last.Raw) {
			return statusError(460)
		}
		root = last
		roots, err := s.rootsFor([]byte(chain))
		if err != nil {
			return err
		}
		for _, cert := range certs {
			if collateral.VerifyCertificateChain(cert, []byte(chain), roots, time.Now()) != nil {
				return statusError(460)
			}
		}
	}
	if err := s.lockMutation(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	entries := make([]cacheEntry, 0)
	stage := func(product, endpoint string, q url.Values, document []byte, header, chain string) error {
		h := make(http.Header)
		h.Set(header, chain)
		r, err := s.validateCollateral(product, endpoint, canonicalQuery(endpoint, q), Response{Body: document, Header: h})
		if err != nil {
			return err
		}
		entries = append(entries, cacheEntry{product, endpoint, canonicalQuery(endpoint, q), r})
		return nil
	}
	seenTCBs := map[string]bool{}
	for _, info := range bundle.Collaterals.TCBInfos {
		var fmspc string
		if json.Unmarshal(info["fmspc"], &fmspc) != nil || !hexLength(fmspc, 6) {
			return statusError(400)
		}
		fmspc = strings.ToUpper(fmspc)
		for _, name := range []string{"sgx_tcbinfo", "sgx_tcbinfo_early", "tdx_tcbinfo", "tdx_tcbinfo_early"} {
			if document, ok := info[name]; ok {
				product, update := "sgx", "standard"
				if strings.HasPrefix(name, "tdx") {
					product = "tdx"
				}
				if strings.HasSuffix(name, "early") {
					update = "early"
				}
				q := url.Values{"fmspc": {fmspc}, "update": {update}}
				key := collateralKey(product, "tcb", q)
				if seenTCBs[key] {
					return statusError(400)
				}
				seenTCBs[key] = true
				if err := stage(product, "tcb", q, document, tcbChainHeader, chains[tcbChainHeader]); err != nil {
					return err
				}
			}
		}
	}
	identities := []struct{ product, endpoint, update, body string }{
		{"sgx", "qe/identity", "standard", bundle.Collaterals.QEIdentity}, {"sgx", "qe/identity", "early", bundle.Collaterals.QEIdentityEarly},
		{"sgx", "qve/identity", "standard", bundle.Collaterals.QVEIdentity}, {"sgx", "qve/identity", "early", bundle.Collaterals.QVEIdentityEarly},
		{"tdx", "qe/identity", "standard", bundle.Collaterals.TDQEIdentity}, {"tdx", "qe/identity", "early", bundle.Collaterals.TDQEIdentityEarly},
	}
	for _, identity := range identities {
		if identity.body != "" {
			if err := stage(identity.product, identity.endpoint, url.Values{"update": {identity.update}}, []byte(identity.body), identityChainHeader, chains[identityChainHeader]); err != nil {
				return err
			}
		}
	}
	for _, item := range []struct{ ca, body string }{{"processor", bundle.Collaterals.PCKCRLs.Processor}, {"platform", bundle.Collaterals.PCKCRLs.Platform}} {
		if item.body != "" {
			if err := stage("sgx", "pckcrl", url.Values{"ca": {item.ca}}, []byte(item.body), pckCRLChainHeader, chains[strings.ToUpper(item.ca)]); err != nil {
				return err
			}
		}
	}
	if bundle.Collaterals.RootCDP != "" && !pcs.IsAllowedCRLURL(bundle.Collaterals.RootCDP) {
		return statusError(400)
	}
	if bundle.Collaterals.RootCRL != "" {
		if root == nil {
			return statusError(460)
		}
		chain := url.PathEscape(string(pemCertificate(root)))
		if err := stage("sgx", "rootcacrl", nil, []byte(bundle.Collaterals.RootCRL), pckCRLChainHeader, chain); err != nil {
			return err
		}
		if bundle.Collaterals.RootCDP != "" {
			entry := entries[len(entries)-1]
			entry.Endpoint = "crl"
			entry.Query = url.Values{"uri": {bundle.Collaterals.RootCDP}}
			entries = append(entries, entry)
		}
	}
	var suppliedCRLs []*x509.RevocationList
	for _, entry := range entries {
		if entry.Endpoint == "pckcrl" || entry.Endpoint == "rootcacrl" {
			crl, err := collateral.ParseCRL(entry.Response.Body)
			if err != nil {
				return statusError(460)
			}
			suppliedCRLs = append(suppliedCRLs, crl)
		}
	}
	for _, chain := range chains {
		if chain == "" {
			continue
		}
		certs, err := collateral.ParseCertificates([]byte(chain))
		if err != nil {
			return statusError(460)
		}
		for _, cert := range certs {
			if err := checkImportRevocation(cert, certs, suppliedCRLs); err != nil {
				return err
			}
		}
	}
	platforms := map[string][]Platform{}
	for _, p := range bundle.Platforms {
		p, err := normalizePlatform(p, false)
		if err != nil {
			return err
		}
		key := platformKey(p.QEID, p.PCEID)
		platforms[key] = append(platforms[key], p)
	}
	records := map[string]*platformRecord{}
	for _, group := range bundle.Collaterals.PCKCerts {
		if group.EncPPID == nil {
			return statusError(400)
		}
		p, err := normalizePlatform(Platform{QEID: group.QEID, PCEID: group.PCEID, EncPPID: *group.EncPPID, PlatformManifest: group.Manifest}, false)
		if err != nil {
			return err
		}
		key := platformKey(p.QEID, p.PCEID)
		if records[key] != nil || len(group.Certs) == 0 {
			return statusError(400)
		}
		record := &platformRecord{}
		if err := s.db.View(func(tx *store.Tx) error { _, err := tx.Get(platformBucket, key, record); return err }); err != nil {
			return err
		}
		if len(platforms[key]) > 0 {
			supplied := platforms[key][0]
			p.EncPPID, p.PlatformManifest = supplied.EncPPID, supplied.PlatformManifest
		} else if record.Platform.QEID != "" {
			p.EncPPID, p.PlatformManifest = record.Platform.EncPPID, record.Platform.PlatformManifest
		}
		record.Platform = p
		record.Certificates = nil
		record.Unavailable = nil
		record.TCBInfos = entries
		for _, cert := range group.Certs {
			if !hexLength(cert.TCBM, 18) || len(cert.TCB) == 0 {
				return statusError(400)
			}
			decoded, err := url.PathUnescape(cert.Cert)
			if err != nil {
				return statusError(400)
			}
			parsed, err := collateral.ParsePCKCertificate([]byte(decoded))
			if err != nil {
				return statusError(460)
			}
			if strings.ToUpper(cert.TCBM) != parsed.TCB.TCBM() {
				return statusError(460)
			}
			if err := matchImportTCB(cert.TCB, parsed.TCB); err != nil {
				return err
			}
			if record.Platform.FMSPC == "" {
				record.Platform.FMSPC, record.Platform.CA = parsed.FMSPC, parsed.CA
			}
			record.Certificates = append(record.Certificates, collateral.PCKCertificate{TCBM: strings.ToUpper(cert.TCBM), Cert: decoded})
		}
		record.IssuerChain = chains[record.Platform.CA]
		if err := s.validatePlatformRecord(record); err != nil {
			return err
		}
		issuers, err := collateral.ParseCertificates([]byte(record.IssuerChain))
		if err != nil {
			return statusError(460)
		}
		for _, cert := range record.Certificates {
			info, err := collateral.ParsePCKCertificate([]byte(cert.Cert))
			if err != nil {
				return statusError(460)
			}
			if err := checkImportRevocation(info.Certificate, issuers, suppliedCRLs); err != nil {
				return err
			}
		}
		var matching []cacheEntry
		for _, entry := range entries {
			if entry.Endpoint == "tcb" && entry.Query.Get("fmspc") == record.Platform.FMSPC {
				matching = append(matching, entry)
			}
		}
		record.TCBInfos = matching
		var sgxTCB bool
		for _, entry := range matching {
			var envelope struct {
				Info struct {
					PCEID string `json:"pceId"`
				} `json:"tcbInfo"`
			}
			if json.Unmarshal(entry.Response.Body, &envelope) != nil || !strings.EqualFold(envelope.Info.PCEID, record.Platform.PCEID) {
				return statusError(460)
			}
			if entry.Product == "sgx" {
				info, err := collateral.ParseTCBInfo(entry.Response.Body)
				if err != nil || info.PCEID != record.Platform.PCEID {
					return statusError(460)
				}
				sgxTCB = true
			}
		}
		if !sgxTCB {
			return statusError(400)
		}
		for _, supplied := range platforms[key] {
			appendRawTCB(record, supplied)
		}
		for _, raw := range record.RawTCBs {
			if _, err := s.selectPlatform(*record, raw); err != nil {
				return statusError(400)
			}
		}
		records[key] = record
	}
	for key := range platforms {
		if records[key] == nil {
			return statusError(400)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(func(tx *store.Tx) error {
		for _, entry := range entries {
			if err := putCollateral(tx, entry.Product, entry.Endpoint, entry.Query, entry.Response); err != nil {
				return err
			}
		}
		for _, record := range records {
			if err := putPlatform(tx, record); err != nil {
				return err
			}
		}
		return nil
	})
}

func matchImportTCB(data []byte, tcb collateral.TCB) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return statusError(400)
	}
	for i, value := range tcb.CPUSVN {
		key := fmt.Sprintf("sgxtcbcomp%02dsvn", i+1)
		var component int
		if raw, ok := fields[key]; !ok || json.Unmarshal(raw, &component) != nil || component != int(value) {
			return statusError(460)
		}
	}
	var pce int
	if raw, ok := fields["pcesvn"]; !ok || json.Unmarshal(raw, &pce) != nil || pce != int(tcb.PCESVN) {
		return statusError(460)
	}
	return nil
}

func pemCertificate(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func checkImportRevocation(cert *x509.Certificate, issuers []*x509.Certificate, crls []*x509.RevocationList) error {
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil {
		return nil
	}
	for _, issuer := range issuers {
		if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) || cert.CheckSignatureFrom(issuer) != nil {
			continue
		}
		for _, crl := range crls {
			if bytes.Equal(crl.RawIssuer, issuer.RawSubject) && crl.CheckSignatureFrom(issuer) == nil && collateral.IsRevoked(crl, cert.SerialNumber) {
				return statusError(460)
			}
		}
	}
	return nil
}
