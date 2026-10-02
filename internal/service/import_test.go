// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/toratako/pccs-go/internal/store"
)

func adminSnapshot(t *testing.T, s *Service) string {
	t.Helper()
	snapshot := map[string]map[string]json.RawMessage{}
	if err := s.db.View(func(tx *store.Tx) error {
		for _, bucket := range []string{platformBucket, collateralBucket, registrationBucket, policyBucket} {
			values := map[string]json.RawMessage{}
			for _, key := range tx.Keys(bucket) {
				var data json.RawMessage
				if _, err := tx.Get(bucket, key, &data); err != nil {
					return err
				}
				values[key] = data
			}
			snapshot[bucket] = values
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func importTestBundle(t *testing.T, f *coreFixture) map[string]any {
	t.Helper()
	tcb := map[string]any{"pcesvn": 1}
	for i := 1; i <= 16; i++ {
		tcb[fmt.Sprintf("sgxtcbcomp%02dsvn", i)] = 1
	}
	nowIdentity := (&coreUpstream{fixture: f})
	identity, err := nowIdentity.Fetch(context.Background(), "sgx", "qe/identity", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"platforms": []any{adminPlatform()},
		"collaterals": map[string]any{
			"version":      4,
			"pck_certs":    []any{map[string]any{"qe_id": "qe", "pce_id": "0000", "enc_ppid": strings.Repeat("ab", 384), "certs": []any{map[string]any{"tcbm": strings.Repeat("01", 16) + "0100", "cert": url.PathEscape(f.pckCert), "tcb": tcb}}}},
			"tcbinfos":     []any{map[string]any{"fmspc": "001122334455", "sgx_tcbinfo": json.RawMessage(f.tcb.Body), "sgx_tcbinfo_early": json.RawMessage(f.tcb.Body)}},
			"certificates": map[string]any{pckChainHeader: map[string]string{"PROCESSOR": f.pckChain, "PLATFORM": f.platformChain}, tcbChainHeader: f.signingChain, identityChainHeader: f.signingChain},
			"pckcacrl":     map[string]string{"processorCrl": hex.EncodeToString(f.pckCRL.Body), "platformCrl": hex.EncodeToString(f.platformCRL.Body)},
			"qeidentity":   string(identity.Body), "rootcacrl": hex.EncodeToString(f.rootCRL), "rootcacrl_cdp": "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
		},
	}
}

func encodeBundle(t *testing.T, bundle map[string]any, indent bool) []byte {
	t.Helper()
	var body []byte
	var err error
	if indent {
		body, err = json.MarshalIndent(bundle, "", "  ")
	} else {
		body, err = json.Marshal(bundle)
	}
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestImportCompleteBundleOffline(t *testing.T) {
	f := newCoreFixture(t)
	u := &coreUpstream{fixture: f, fail: true}
	s := newAdminService(t, "OFFLINE", u)
	ctx := context.Background()
	if err := s.Import(ctx, encodeBundle(t, importTestBundle(t, f), true)); err != nil {
		t.Fatal(err)
	}
	response, err := s.Get(ctx, "sgx", "pckcert", coreQuery())
	if err != nil || string(response.Body) != f.pckCert {
		t.Fatalf("imported PCK: %v", err)
	}
	for _, endpoint := range []string{"qe/identity", "rootcacrl"} {
		if _, err := s.Get(ctx, "sgx", endpoint, nil); err != nil {
			t.Fatal(err)
		}
	}
	response, err = s.Get(ctx, "sgx", "pckcrl", url.Values{"ca": {"processor"}, "encoding": {"der"}})
	if err != nil || !bytes.Equal(response.Body, f.pckCRL.Body) {
		t.Fatalf("imported CRL: %v", err)
	}
	response, err = s.Get(ctx, "sgx", "crl", url.Values{"uri": {"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"}})
	if err != nil || !bytes.Equal(response.Body, f.rootCRL) {
		t.Fatalf("imported root CDP: %v", err)
	}
	platforms, err := s.Platforms(ctx, "[]")
	if err != nil || len(platforms) != 1 {
		t.Fatalf("cached platforms: %v %v", platforms, err)
	}
	if u.calls != 0 {
		t.Fatalf("offline import contacted PCS %d times", u.calls)
	}
}

func TestImportRejectsInvalidBundleWithoutMutation(t *testing.T) {
	f := newCoreFixture(t)
	s := newAdminService(t, "OFFLINE", nil)
	ctx := context.Background()
	if err := s.Import(ctx, encodeBundle(t, importTestBundle(t, f), false)); err != nil {
		t.Fatal(err)
	}
	before := adminSnapshot(t, s)
	mutations := map[string]func(map[string]any){
		"version":     func(b map[string]any) { b["collaterals"].(map[string]any)["version"] = 3 },
		"missing TCB": func(b map[string]any) { b["collaterals"].(map[string]any)["tcbinfos"] = []any{} },
		"missing encrypted PPID field": func(b map[string]any) {
			delete(b["collaterals"].(map[string]any)["pck_certs"].([]any)[0].(map[string]any), "enc_ppid")
		},
		"invalid cert": func(b map[string]any) {
			b["collaterals"].(map[string]any)["pck_certs"].([]any)[0].(map[string]any)["certs"].([]any)[0].(map[string]any)["cert"] = "invalid"
		},
		"TCBM mismatch": func(b map[string]any) {
			b["collaterals"].(map[string]any)["pck_certs"].([]any)[0].(map[string]any)["certs"].([]any)[0].(map[string]any)["tcbm"] = strings.Repeat("02", 16) + "0200"
		},
		"TCB metadata mismatch": func(b map[string]any) {
			b["collaterals"].(map[string]any)["pck_certs"].([]any)[0].(map[string]any)["certs"].([]any)[0].(map[string]any)["tcb"].(map[string]any)["pcesvn"] = 2
		},
		"unmatched platform": func(b map[string]any) { p := adminPlatform(); p.QEID = "OTHER"; b["platforms"] = []any{p} },
		"bad identity signature": func(b map[string]any) {
			body := b["collaterals"].(map[string]any)["qeidentity"].(string)
			b["collaterals"].(map[string]any)["qeidentity"] = strings.Replace(body, "QE", "QVE", 1)
		},
		"bad root CRL":    func(b map[string]any) { b["collaterals"].(map[string]any)["rootcacrl"] = "010203" },
		"unsafe root CDP": func(b map[string]any) { b["collaterals"].(map[string]any)["rootcacrl_cdp"] = "http://127.0.0.1/secret" },
		"different roots": func(b map[string]any) {
			other := newCoreFixture(t)
			b["collaterals"].(map[string]any)["certificates"].(map[string]any)[identityChainHeader] = other.signingChain
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bundle := importTestBundle(t, f)
			mutate(bundle)
			if err := s.Import(ctx, encodeBundle(t, bundle, false)); err == nil {
				t.Fatal("invalid bundle accepted")
			}
			if got := adminSnapshot(t, s); got != before {
				t.Fatal("invalid import changed stored data")
			}
		})
	}
	for _, body := range [][]byte{[]byte(`{"platforms":[],"platforms":[],"collaterals":{}}`), []byte(`{"platforms":[],"collaterals":{"version":4,"pck_certs":[],"tcbinfos":[],"certificates":{"SGX-PCK-Certificate-Issuer-Chain":{}}}} {}`)} {
		requireCoreStatus(t, s.Import(ctx, body), 400)
		if adminSnapshot(t, s) != before {
			t.Fatal("malformed import changed store")
		}
	}
}

func TestImportPinnedRootsAndPreservedRawTCBs(t *testing.T) {
	f := newCoreFixture(t)
	s := newAdminService(t, "OFFLINE", nil)
	ctx := context.Background()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(f.rootPEM)) {
		t.Fatal("root fixture")
	}
	s.cfg.Roots = roots
	if err := s.Import(ctx, encodeBundle(t, importTestBundle(t, f), false)); err != nil {
		t.Fatal(err)
	}
	query := coreQuery()
	query.Set("cpusvn", strings.Repeat("03", 16))
	query.Set("pcesvn", "0300")
	if _, err := s.Get(ctx, "sgx", "pckcert", query); err != nil {
		t.Fatal(err)
	}
	if err := s.Import(ctx, encodeBundle(t, importTestBundle(t, f), false)); err != nil {
		t.Fatal(err)
	}
	platforms, err := s.Platforms(ctx, "[]")
	if err != nil || len(platforms) != 2 {
		t.Fatalf("raw TCBs not preserved: %v %v", platforms, err)
	}
	other := newCoreFixture(t)
	before := adminSnapshot(t, s)
	requireCoreStatus(t, s.Import(ctx, encodeBundle(t, importTestBundle(t, other), false)), 460)
	if adminSnapshot(t, s) != before {
		t.Fatal("untrusted import changed cache")
	}
}

func TestImportAllowsAbsentCRLsAndFutureSignedFields(t *testing.T) {
	f := newCoreFixture(t)
	s := newAdminService(t, "OFFLINE", nil)
	ctx := context.Background()
	bundle := importTestBundle(t, f)
	collaterals := bundle["collaterals"].(map[string]any)
	delete(collaterals, "pckcacrl")
	delete(collaterals, "rootcacrl")
	delete(collaterals, "rootcacrl_cdp")
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(f.tcb.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope["tcbInfo"], &payload); err != nil {
		t.Fatal(err)
	}
	payload["futureSignedMetadata"] = map[string]any{"version": 9, "description": "forward compatible"}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := f.makeSigned("tcbInfo", encoded)
	info := collaterals["tcbinfos"].([]any)[0].(map[string]any)
	info["sgx_tcbinfo"] = json.RawMessage(signed)
	info["sgx_tcbinfo_early"] = json.RawMessage(signed)
	if err := s.Import(ctx, encodeBundle(t, bundle, true)); err != nil {
		t.Fatal(err)
	}
	response, err := s.Get(ctx, "sgx", "tcb", url.Values{"fmspc": {"001122334455"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response.Body, []byte("futureSignedMetadata")) {
		t.Fatal("signed unknown fields were discarded")
	}
}

func TestImportRejectsRevokedCertificatesAtomically(t *testing.T) {
	f := newCoreFixture(t)
	s := newAdminService(t, "OFFLINE", nil)
	ctx := context.Background()
	if err := s.Import(ctx, encodeBundle(t, importTestBundle(t, f), false)); err != nil {
		t.Fatal(err)
	}
	before := adminSnapshot(t, s)
	for _, test := range []struct {
		name   string
		root   bool
		serial int64
	}{{"PCK leaf", false, 4}, {"PCK CA", true, 2}, {"collateral signer", true, 3}} {
		t.Run(test.name, func(t *testing.T) {
			bundle := importTestBundle(t, f)
			collaterals := bundle["collaterals"].(map[string]any)
			crl := hex.EncodeToString(f.makeRevokedCRL(test.root, test.serial))
			if test.root {
				collaterals["rootcacrl"] = crl
			} else {
				collaterals["pckcacrl"].(map[string]string)["processorCrl"] = crl
			}
			requireCoreStatus(t, s.Import(ctx, encodeBundle(t, bundle, false)), 460)
			if adminSnapshot(t, s) != before {
				t.Fatal("revoked certificate import changed stored data")
			}
		})
	}
	// A valid CRL for another CA must not revoke an unrelated certificate.
	bundle := importTestBundle(t, f)
	bundle["collaterals"].(map[string]any)["rootcacrl"] = hex.EncodeToString(f.makeRevokedCRL(true, 4))
	if err := s.Import(ctx, encodeBundle(t, bundle, false)); err != nil {
		t.Fatalf("root CRL incorrectly revoked processor-issued leaf: %v", err)
	}
}
