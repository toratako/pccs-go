// Copyright (C) 2026 toratako and contributors
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
	"sync"
	"testing"

	"github.com/toratako/pccs-go/internal/pcs"
	"github.com/toratako/pccs-go/internal/store"
)

func newAdminService(t *testing.T, mode string, u Upstream) *Service {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Config{Mode: mode}, db, u)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func adminPlatform() Platform {
	q := coreQuery()
	return Platform{QEID: strings.ToLower(q.Get("qeid")), PCEID: q.Get("pceid"), CPUSVN: q.Get("cpusvn"), PCESVN: q.Get("pcesvn"), EncPPID: q.Get("encrypted_ppid")}
}

func TestOfflineRegistrationAndAtomicDrain(t *testing.T) {
	u := &coreUpstream{fail: true}
	s := newAdminService(t, "OFFLINE", u)
	ctx := context.Background()
	p := adminPlatform()
	if err := s.Register(ctx, p, "all"); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(ctx, p, "standard"); err != nil {
		t.Fatal(err)
	}
	if u.calls != 0 {
		t.Fatalf("OFFLINE contacted PCS %d times", u.calls)
	}
	var wg sync.WaitGroup
	counts := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			platforms, err := s.Platforms(ctx, "reg")
			if err != nil {
				t.Error(err)
			}
			counts <- len(platforms)
		}()
	}
	wg.Wait()
	close(counts)
	total := 0
	for n := range counts {
		total += n
	}
	if total != 1 {
		t.Fatalf("drained %d registrations, want exactly one", total)
	}
	p.PlatformManifest = "manifest"
	p.CPUSVN = ""
	p.PCESVN = ""
	p.EncPPID = ""
	if err := s.Register(ctx, p, ""); err != nil {
		t.Fatal(err)
	}
	platforms, err := s.Platforms(ctx, "")
	if err != nil || len(platforms) != 1 {
		t.Fatalf("manifest queue: %v %v", platforms, err)
	}
	if platforms[0].QEID != "QE" || platforms[0].CPUSVN != "" || platforms[0].EncPPID != "" {
		t.Fatalf("normalization: %+v", platforms[0])
	}
	requireCoreStatus(t, s.Refresh(ctx, "", ""), 503)
}

func TestRegisterModesAndQueueFailures(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"REQ", "LAZY"} {
		t.Run(mode, func(t *testing.T) {
			f := newCoreFixture(t)
			u := &coreUpstream{fixture: f, fail: true}
			s := newAdminService(t, mode, u)
			requireCoreStatus(t, s.Register(ctx, adminPlatform(), "standard"), 502)
			queued, err := s.Platforms(ctx, "reg")
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "REQ" {
				want = 1
			}
			if len(queued) != want {
				t.Fatalf("queue length %d, want %d", len(queued), want)
			}
			u.fail = false
			if err := s.Register(ctx, adminPlatform(), "all"); err != nil {
				t.Fatal(err)
			}
			queued, err = s.Platforms(ctx, "reg")
			if err != nil || len(queued) != 0 {
				t.Fatalf("completed registration remains queued: %v %v", queued, err)
			}
			for _, q := range []url.Values{{"update": {"early"}}, {"update": {"standard"}}} {
				if _, err := s.Get(ctx, "tdx", "qe/identity", q); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Get(ctx, "sgx", "rootcacrl", nil); err != nil {
				t.Fatal(err)
			}
			calls := u.calls
			if err := s.Register(ctx, adminPlatform(), "all"); err != nil {
				t.Fatal(err)
			}
			if u.calls != calls {
				t.Fatalf("cached registration fetched PCS: %d -> %d", calls, u.calls)
			}
			platforms, err := s.Platforms(ctx, "[001122334455]")
			if err != nil || len(platforms) != 1 {
				t.Fatalf("cached filter: %v %v", platforms, err)
			}
			platforms, err = s.Platforms(ctx, "[ffffffffffff]")
			if err != nil || len(platforms) != 0 {
				t.Fatalf("nonmatching filter: %v %v", platforms, err)
			}
		})
	}
}

func TestRegistrationValidation(t *testing.T) {
	s := newAdminService(t, "OFFLINE", nil)
	ctx := context.Background()
	for _, change := range []func(*Platform){func(p *Platform) { p.QEID = "" }, func(p *Platform) { p.PCEID = "1" }, func(p *Platform) { p.CPUSVN = "xx" }, func(p *Platform) { p.PCESVN = "" }, func(p *Platform) { p.EncPPID = "" }} {
		p := adminPlatform()
		change(&p)
		requireCoreStatus(t, s.Register(ctx, p, "standard"), 400)
	}
	requireCoreStatus(t, s.Register(ctx, adminPlatform(), "unknown"), 400)
	for _, source := range []string{"001122334455", "[001122334455;001122334455]", "[invalid]", "[001122334455,]"} {
		_, err := s.Platforms(ctx, source)
		requireCoreStatus(t, err, 400)
	}
}

func TestOfflineRegistrationQueuesUnmappedRawTCB(t *testing.T) {
	f := newCoreFixture(t)
	s := newAdminService(t, "OFFLINE", nil)
	ctx := context.Background()
	if err := s.Import(ctx, encodeBundle(t, importTestBundle(t, f), false)); err != nil {
		t.Fatal(err)
	}
	p := adminPlatform()
	p.CPUSVN = strings.Repeat("03", 16)
	p.PCESVN = "0300"
	if err := s.Register(ctx, p, "standard"); err != nil {
		t.Fatal(err)
	}
	queued, err := s.Platforms(ctx, "reg")
	if err != nil || len(queued) != 1 || queued[0].CPUSVN != p.CPUSVN {
		t.Fatalf("unmapped raw TCB not queued: %v %v", queued, err)
	}
}

func policyJWT(t *testing.T, class string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"policy_array": []any{map[string]any{"environment": map[string]string{"class_id": class}}}})
	body, _ := json.Marshal(map[string]string{"policy_payload": string(payload)})
	return "header." + base64.RawURLEncoding.EncodeToString(body) + ".signature"
}

func TestPolicyDefaultsAndValidation(t *testing.T) {
	s := newAdminService(t, "OFFLINE", nil)
	ctx := context.Background()
	classes := []string{"3123ec35-8d38-4ea5-87a5-d6c48b567570", "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f", "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3"}
	for typ, class := range classes {
		jwt := policyJWT(t, class)
		body, _ := json.Marshal(map[string]any{"fmspc": "aabbccddeeff", "is_default": true, "policy": jwt})
		id, err := s.PutPolicy(ctx, body)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha512.Sum384([]byte(jwt))
		if id != hex.EncodeToString(digest[:]) {
			t.Fatal("policy ID is not SHA384")
		}
		got, err := s.Policies(ctx, "AABBCCDDEEFF")
		if err != nil || got != jwt {
			t.Fatalf("default policy: %s %v", got, err)
		}
		_ = s.db.View(func(tx *store.Tx) error {
			var record policyRecord
			if _, err := tx.Get(policyBucket, id, &record); err != nil {
				t.Fatal(err)
			}
			if record.Type != typ {
				t.Fatalf("type %d, want %d", record.Type, typ)
			}
			return nil
		})
	}
	_, err := s.Policies(ctx, "ffffffffffff")
	requireCoreStatus(t, err, 404)
	for _, body := range [][]byte{[]byte(`{"fmspc":"aabbccddeeff","policy":"x.y"}`), []byte(`{"is_default":true,"fmspc":"aabbccddeeff","policy":"x.y"}`), []byte(`{"is_default":true,"is_default":false,"fmspc":"aabbccddeeff","policy":"x.y"}`)} {
		_, err := s.PutPolicy(ctx, body)
		requireCoreStatus(t, err, 400)
	}
	for _, class := range []string{"unknown", "3769258c-75e6-4bc7-8d72-d2b0e224cad2"} {
		body, _ := json.Marshal(map[string]any{"fmspc": "aabbccddeeff", "is_default": true, "policy": policyJWT(t, class)})
		_, err := s.PutPolicy(ctx, body)
		requireCoreStatus(t, err, 400)
	}
}

func TestRefreshRollbackAndFilters(t *testing.T) {
	f := newCoreFixture(t)
	u := &coreUpstream{fixture: f}
	s := newAdminService(t, "LAZY", u)
	ctx := context.Background()
	if _, err := s.Get(ctx, "sgx", "pckcert", coreQuery()); err != nil {
		t.Fatal(err)
	}
	before := adminSnapshot(t, s)
	u.badTCB = true
	requireCoreStatus(t, s.Refresh(ctx, "certs", "001122334455"), 460)
	if got := adminSnapshot(t, s); got != before {
		t.Fatal("failed cert refresh changed cache")
	}
	u.badTCB = false
	calls := u.calls
	if err := s.Refresh(ctx, "certs", "[ffffffffffff]"); err != nil {
		t.Fatal(err)
	}
	if u.calls != calls {
		t.Fatal("nonmatching FMSPC refresh contacted upstream")
	}
	if err := s.Refresh(ctx, "certs", "[]"); err != nil {
		t.Fatal(err)
	}
	before = adminSnapshot(t, s)
	u.fail = true
	requireCoreStatus(t, s.Refresh(ctx, "", ""), 502)
	if got := adminSnapshot(t, s); got != before {
		t.Fatal("failed collateral refresh changed cache")
	}
	u.fail = false
	if err := s.Refresh(ctx, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "tdx", "qe/identity", url.Values{"update": {"early"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "sgx", "rootcacrl", nil); err != nil {
		t.Fatal(err)
	}
	requireCoreStatus(t, s.Refresh(ctx, "invalid", ""), 400)
}

type adminLateFailure struct {
	*coreUpstream
	rootFailure           bool
	secondPlatformFailure bool
	missingIdentity       bool
	badIdentity           bool
}

func (u *adminLateFailure) Fetch(ctx context.Context, product, endpoint string, q url.Values) (pcs.Response, error) {
	if product == "sgx" && endpoint == "qe/identity" && q.Get("update") == "early" {
		if u.missingIdentity {
			return pcs.Response{StatusCode: 404}, &pcs.StatusError{StatusCode: 404}
		}
		if u.badIdentity {
			response, err := u.coreUpstream.Fetch(ctx, product, endpoint, q)
			if err != nil {
				return response, err
			}
			response.Body = append(response.Body, byte('!'))
			return response, nil
		}
	}
	return u.coreUpstream.Fetch(ctx, product, endpoint, q)
}

func (u *adminLateFailure) FetchCRL(ctx context.Context, uri string) (pcs.Response, error) {
	if u.rootFailure {
		return pcs.Response{}, errors.New("root download failed")
	}
	return u.coreUpstream.FetchCRL(ctx, uri)
}

func (u *adminLateFailure) FetchPCKCertificates(ctx context.Context, enc, pce, manifest string) (pcs.Response, error) {
	if u.secondPlatformFailure && strings.HasPrefix(enc, "cd") {
		return pcs.Response{}, errors.New("second platform unavailable")
	}
	return u.coreUpstream.FetchPCKCertificates(ctx, enc, pce, manifest)
}

func TestRefreshRollsBackAfterSuccessfulStaging(t *testing.T) {
	f := newCoreFixture(t)
	u := &adminLateFailure{coreUpstream: &coreUpstream{fixture: f}, rootFailure: true}
	s := newAdminService(t, "LAZY", u)
	ctx := context.Background()
	before := adminSnapshot(t, s)
	requireCoreStatus(t, s.Refresh(ctx, "", ""), 502)
	if u.calls != 6 {
		t.Fatalf("expected six staged identities, got %d calls", u.calls)
	}
	if adminSnapshot(t, s) != before {
		t.Fatal("root failure committed already staged identities")
	}
	u.rootFailure = false
	bundle := importTestBundle(t, f)
	p := adminPlatform()
	p.QEID = "SECOND"
	p.EncPPID = strings.Repeat("cd", 384)
	bundle["platforms"] = append(bundle["platforms"].([]any), p)
	collaterals := bundle["collaterals"].(map[string]any)
	groups := collaterals["pck_certs"].([]any)
	first := groups[0].(map[string]any)
	second := map[string]any{"qe_id": p.QEID, "pce_id": p.PCEID, "enc_ppid": p.EncPPID, "certs": first["certs"]}
	collaterals["pck_certs"] = append(groups, second)
	if err := s.Import(ctx, encodeBundle(t, bundle, false)); err != nil {
		t.Fatal(err)
	}
	before = adminSnapshot(t, s)
	calls := u.calls
	u.secondPlatformFailure = true
	requireCoreStatus(t, s.Refresh(ctx, "certs", "all"), 502)
	if u.calls <= calls {
		t.Fatal("first platform was not staged")
	}
	if adminSnapshot(t, s) != before {
		t.Fatal("second platform failure committed first staged platform")
	}
}

func TestCachedRegistrationRecordsNewRawTCB(t *testing.T) {
	for _, mode := range []string{"REQ", "LAZY"} {
		t.Run(mode, func(t *testing.T) {
			f := newCoreFixture(t)
			u := &coreUpstream{fixture: f}
			s := newAdminService(t, mode, u)
			ctx := context.Background()
			if err := s.Register(ctx, adminPlatform(), "all"); err != nil {
				t.Fatal(err)
			}
			calls := u.calls
			p := adminPlatform()
			p.CPUSVN = strings.Repeat("03", 16)
			p.PCESVN = "0300"
			if err := s.Register(ctx, p, "all"); err != nil {
				t.Fatal(err)
			}
			if u.calls != calls {
				t.Fatal("cached certificate registration refetched PCS")
			}
			platforms, err := s.Platforms(ctx, "[]")
			if err != nil || len(platforms) != 2 {
				t.Fatalf("new raw TCB not recorded: %v %v", platforms, err)
			}
			queued, err := s.Platforms(ctx, "reg")
			if err != nil || len(queued) != 0 {
				t.Fatalf("cached registration queued: %v %v", queued, err)
			}
		})
	}
}

func TestRefreshPreservesMissingIdentityAndRejectsIntegrityFailure(t *testing.T) {
	f := newCoreFixture(t)
	u := &adminLateFailure{coreUpstream: &coreUpstream{fixture: f}}
	s := newAdminService(t, "LAZY", u)
	ctx := context.Background()
	q := url.Values{"update": {"early"}}
	old, err := s.Get(ctx, "sgx", "qe/identity", q)
	if err != nil {
		t.Fatal(err)
	}
	u.missingIdentity = true
	if err := s.Refresh(ctx, "", ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "sgx", "qe/identity", q)
	if err != nil || string(got.Body) != string(old.Body) {
		t.Fatal("404 refresh did not preserve cached identity")
	}
	u.missingIdentity = false
	u.badIdentity = true
	before := adminSnapshot(t, s)
	requireCoreStatus(t, s.Refresh(ctx, "", ""), 460)
	if adminSnapshot(t, s) != before {
		t.Fatal("identity integrity error partially committed refresh")
	}
}
