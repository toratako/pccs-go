// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/toratako/pccs-go/internal/pcs"
	"github.com/toratako/pccs-go/internal/store"
)

type coreFixture struct {
	t                                                       *testing.T
	signer                                                  *ecdsa.PrivateKey
	pckCert, pckChain, platformChain, signingChain, rootPEM string
	tcb, pck, pckCRL, platformCRL                           pcs.Response
	rootCRL                                                 []byte
	makeRevokedCRL                                          func(root bool, serial int64) []byte
}

func newCoreFixture(t *testing.T) *coreFixture {
	t.Helper()
	f := &coreFixture{t: t}
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now()
	newCert := func(serial int, cn string, ca bool) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(int64(serial)), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{byte(serial)}, CRLDistributionPoints: []string{"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"}}
	}
	issue := func(template, parent *x509.Certificate, key, issuer *ecdsa.PrivateKey) (*x509.Certificate, string) {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, issuer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	rootKey := newKey()
	rootT := newCert(1, "Intel SGX Root CA", true)
	root, rootPEM := issue(rootT, rootT, rootKey, rootKey)
	f.rootPEM = rootPEM
	caKey := newKey()
	ca, caPEM := issue(newCert(2, "Intel SGX PCK Processor CA", true), root, caKey, rootKey)
	f.pckChain = url.PathEscape(caPEM + rootPEM)
	f.signer = newKey()
	_, signerPEM := issue(newCert(3, "Intel SGX TCB Signing", false), root, f.signer, rootKey)
	f.signingChain = url.PathEscape(signerPEM + rootPEM)
	marshal := func(value any) []byte {
		data, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	oid := asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	entry := func(suffix []int, value any) asn1.RawValue {
		identifier := append(append(asn1.ObjectIdentifier(nil), oid...), suffix...)
		raw := marshal(struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue
		}{identifier, asn1.RawValue{FullBytes: marshal(value)}})
		return asn1.RawValue{FullBytes: raw}
	}
	cpu := bytes.Repeat([]byte{1}, 16)
	var tcbs []asn1.RawValue
	for i := 1; i <= 16; i++ {
		tcbs = append(tcbs, entry([]int{2, i}, 1))
	}
	tcbs = append(tcbs, entry([]int{2, 17}, 1), entry([]int{2, 18}, cpu))
	ext := marshal([]asn1.RawValue{entry([]int{1}, bytes.Repeat([]byte{7}, 16)), entry([]int{2}, tcbs), entry([]int{3}, []byte{0, 0}), entry([]int{4}, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55})})
	pckT := newCert(4, "Intel SGX PCK Certificate", false)
	pckT.ExtraExtensions = []pkix.Extension{{Id: oid, Value: ext}}
	_, f.pckCert = issue(pckT, ca, newKey(), caKey)
	components := make([]map[string]int, 16)
	for i := range components {
		components[i] = map[string]int{"svn": 1}
	}
	payload, _ := json.Marshal(map[string]any{"id": "SGX", "version": 3, "fmspc": "001122334455", "pceId": "0000", "tcbType": 0, "issueDate": now.Add(-time.Minute).UTC().Format(time.RFC3339), "nextUpdate": now.Add(time.Hour).UTC().Format(time.RFC3339), "tcbLevels": []any{map[string]any{"tcb": map[string]any{"sgxtcbcomponents": components, "pcesvn": 1}, "tcbStatus": "UpToDate"}}})
	f.tcb = pcs.Response{StatusCode: 200, Header: http.Header{http.CanonicalHeaderKey(tcbChainHeader): {f.signingChain}}, Body: f.makeSigned("tcbInfo", payload)}
	pckBody, _ := json.Marshal([]map[string]string{{"tcbm": strings.Repeat("01", 16) + "0100", "cert": url.PathEscape(f.pckCert)}})
	f.pck = pcs.Response{StatusCode: 200, Header: http.Header{http.CanonicalHeaderKey(pckChainHeader): {f.pckChain}, "Sgx-Fmspc": {"001122334455"}, "Sgx-Pck-Certificate-Ca-Type": {"PROCESSOR"}}, Body: pckBody}
	crl := func(issuer *x509.Certificate, key *ecdsa.PrivateKey) []byte {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, issuer, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	f.rootCRL = crl(root, rootKey)
	f.pckCRL = pcs.Response{StatusCode: 200, Header: http.Header{http.CanonicalHeaderKey(pckCRLChainHeader): {f.pckChain}}, Body: crl(ca, caKey)}
	platformKey := newKey()
	platformCA, platformPEM := issue(newCert(5, "Intel SGX PCK Platform CA", true), root, platformKey, rootKey)
	f.platformChain = url.PathEscape(platformPEM + rootPEM)
	f.platformCRL = pcs.Response{StatusCode: 200, Header: http.Header{http.CanonicalHeaderKey(pckCRLChainHeader): {f.platformChain}}, Body: crl(platformCA, platformKey)}
	f.makeRevokedCRL = func(useRoot bool, serial int64) []byte {
		issuer, key := ca, caKey
		if useRoot {
			issuer, key = root, rootKey
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(serial), RevocationTime: now.Add(-time.Minute), ReasonCode: 1}}}, issuer, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	return f
}

func (f *coreFixture) makeSigned(field string, payload []byte) []byte {
	f.t.Helper()
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, f.signer, digest[:])
	if err != nil {
		f.t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	body, err := json.Marshal(map[string]any{field: json.RawMessage(payload), "signature": hex.EncodeToString(signature)})
	if err != nil {
		f.t.Fatal(err)
	}
	return body
}

type coreUpstream struct {
	fixture        *coreFixture
	calls          int
	tcbCalls       []string
	manifest       string
	fail           bool
	earlyMissing   bool
	badTCB         bool
	unavailable    bool
	allUnavailable bool
}

func (u *coreUpstream) Fetch(_ context.Context, product, endpoint string, q url.Values) (pcs.Response, error) {
	u.calls++
	if u.fail {
		return pcs.Response{}, errors.New("network failure")
	}
	if endpoint == "tcb" {
		u.tcbCalls = append(u.tcbCalls, product+"/"+q.Get("update"))
		if product == "tdx" || (u.earlyMissing && q.Get("update") == "early") {
			return pcs.Response{StatusCode: 404}, &pcs.StatusError{StatusCode: 404}
		}
		response := u.fixture.tcb
		if u.badTCB {
			response.Body = append(bytes.Clone(response.Body), byte('!'))
		}
		return response, nil
	}
	if endpoint == "pckcrl" {
		if strings.EqualFold(q.Get("ca"), "platform") {
			return u.fixture.platformCRL, nil
		}
		return u.fixture.pckCRL, nil
	}
	if endpoint == "qe/identity" || endpoint == "qve/identity" {
		id := "QE"
		if endpoint == "qve/identity" {
			id = "QVE"
		} else if product == "tdx" {
			id = "TD_QE"
		}
		now := time.Now()
		payload, _ := json.Marshal(map[string]any{"id": id, "issueDate": now.Add(-time.Minute).UTC().Format(time.RFC3339), "nextUpdate": now.Add(time.Hour).UTC().Format(time.RFC3339)})
		return pcs.Response{StatusCode: 200, Header: http.Header{http.CanonicalHeaderKey(identityChainHeader): {u.fixture.signingChain}}, Body: u.fixture.makeSigned("enclaveIdentity", payload)}, nil
	}
	return pcs.Response{StatusCode: 404}, &pcs.StatusError{StatusCode: 404}
}

func (u *coreUpstream) FetchPCKCertificates(_ context.Context, _ string, _ string, manifest string) (pcs.Response, error) {
	u.calls++
	u.manifest = manifest
	if u.fail {
		return pcs.Response{}, errors.New("network failure")
	}
	response := u.fixture.pck
	if u.allUnavailable {
		response.Body, _ = json.Marshal([]map[string]string{{"tcbm": strings.Repeat("02", 16) + "0200", "cert": "Not available"}})
		return response, nil
	}
	if u.unavailable {
		var body []map[string]string
		_ = json.Unmarshal(response.Body, &body)
		body = append(body, map[string]string{"tcbm": strings.Repeat("02", 16) + "0200", "cert": "Not available"})
		response.Body, _ = json.Marshal(body)
	}
	return response, nil
}
func (u *coreUpstream) FetchCRL(_ context.Context, _ string) (pcs.Response, error) {
	u.calls++
	if u.fail {
		return pcs.Response{}, errors.New("network failure")
	}
	return pcs.Response{StatusCode: 200, Header: make(http.Header), Body: u.fixture.rootCRL}, nil
}

func coreQuery() url.Values {
	return url.Values{"qeid": {"QE"}, "pceid": {"0000"}, "cpusvn": {strings.Repeat("02", 16)}, "pcesvn": {"0200"}, "encrypted_ppid": {strings.Repeat("ab", 384)}}
}
func requireCoreStatus(t *testing.T, err error, code int) {
	t.Helper()
	var status *StatusError
	if !errors.As(err, &status) || status.StatusCode != code {
		t.Fatalf("got %v; want status %d", err, code)
	}
}

func TestCoreLazyPCKWarmRestartAndSelection(t *testing.T) {
	f := newCoreFixture(t)
	up := &coreUpstream{fixture: f}
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{}, db, up)
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.Get(context.Background(), "sgx", "pckcert", coreQuery())
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != f.pckCert || response.Header.Get("SGX-TCBm") != strings.Repeat("01", 16)+"0100" {
		t.Fatal("wrong PCK selection")
	}
	if strings.Join(up.tcbCalls, ",") != "sgx/early,sgx/standard,tdx/early,tdx/standard" {
		t.Fatalf("TCB warming %v", up.tcbCalls)
	}
	before := up.calls
	q := coreQuery()
	q.Set("cpusvn", strings.Repeat("03", 16))
	if _, err = s.Get(context.Background(), "sgx", "pckcert", q); err != nil {
		t.Fatal(err)
	}
	if up.calls != before {
		t.Fatal("cached platform fetched PCS")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err = New(Config{Mode: "OFFLINE"}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(context.Background(), "sgx", "pckcert", q); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(context.Background(), "sgx", "tcb", url.Values{"fmspc": {"001122334455"}, "update": {"EARLY"}}); err != nil {
		t.Fatal(err)
	}
}

func TestCoreModesDoNotFetchMisses(t *testing.T) {
	for _, mode := range []string{"REQ", "OFFLINE"} {
		t.Run(mode, func(t *testing.T) {
			db, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			up := &coreUpstream{}
			s, err := New(Config{Mode: mode}, db, up)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Get(context.Background(), "sgx", "pckcert", coreQuery())
			requireCoreStatus(t, err, 461)
			_, err = s.Get(context.Background(), "sgx", "tcb", url.Values{"fmspc": {"001122334455"}})
			requireCoreStatus(t, err, 404)
			if up.calls != 0 {
				t.Fatal("PCS called on non-LAZY miss")
			}
		})
	}
}

func TestCoreBadTCBDoesNotPersistPlatform(t *testing.T) {
	f := newCoreFixture(t)
	up := &coreUpstream{fixture: f, badTCB: true}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := New(Config{}, db, up)
	_, err = s.Get(context.Background(), "sgx", "pckcert", coreQuery())
	requireCoreStatus(t, err, 460)
	_ = db.View(func(tx *store.Tx) error {
		if len(tx.Keys(platformBucket)) != 0 || len(tx.Keys(collateralBucket)) != 0 {
			t.Fatal("failed validation persisted data")
		}
		return nil
	})
}

func TestCoreCRLEncodingsAndRoot(t *testing.T) {
	f := newCoreFixture(t)
	up := &coreUpstream{fixture: f}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := New(Config{}, db, up)
	legacy, err := s.Get(context.Background(), "sgx", "pckcrl", url.Values{"ca": {"PROCESSOR"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(legacy.Body) != hex.EncodeToString(f.pckCRL.Body) {
		t.Fatal("legacy PCK CRL encoding")
	}
	calls := up.calls
	der, err := s.Get(context.Background(), "sgx", "pckcrl", url.Values{"ca": {"processor"}, "encoding": {"DER"}})
	if err != nil || !bytes.Equal(der.Body, f.pckCRL.Body) || calls != up.calls {
		t.Fatalf("DER cache response: %v", err)
	}
	root, err := s.Get(context.Background(), "sgx", "rootcacrl", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(root.Body) != hex.EncodeToString(f.rootCRL) {
		t.Fatal("root CRL encoding")
	}
	if root.Header.Get("Content-Type") != "application/pkix-crl" {
		t.Fatal("root CRL content type")
	}
}

func TestCoreIdentitiesAndGenericCRL(t *testing.T) {
	f := newCoreFixture(t)
	up := &coreUpstream{fixture: f}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := New(Config{}, db, up)
	for _, item := range [][2]string{{"sgx", "qe/identity"}, {"sgx", "qve/identity"}, {"tdx", "qe/identity"}} {
		if _, err = s.Get(context.Background(), item[0], item[1], url.Values{"update": {"EARLY"}}); err != nil {
			t.Fatal(err)
		}
	}
	q := url.Values{"uri": {"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"}}
	response, err := s.Get(context.Background(), "sgx", "crl", q)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Body, f.rootCRL) {
		t.Fatal("generic CRL must preserve DER")
	}
	before := up.calls
	if _, err = s.Get(context.Background(), "sgx", "crl", q); err != nil {
		t.Fatal(err)
	}
	if before != up.calls {
		t.Fatal("generic CRL cache miss")
	}
}

func TestCoreStagedStandardIgnoresOldEarly(t *testing.T) {
	f := newCoreFixture(t)
	up := &coreUpstream{fixture: f, earlyMissing: true}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := New(Config{}, db, up)
	bad := Response{Body: []byte(`{"tcbInfo":{"pceId":"FFFF"}}`), Header: make(http.Header)}
	if err = db.Update(func(tx *store.Tx) error {
		return putCollateral(tx, "sgx", "tcb", url.Values{"fmspc": {"001122334455"}, "update": {"early"}}, bad)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(context.Background(), "sgx", "pckcert", coreQuery()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(context.Background(), "sgx", "pckcert", coreQuery()); err != nil {
		t.Fatal("cached standard fallback:", err)
	}
}

func TestCoreManifestAndUnavailable(t *testing.T) {
	f := newCoreFixture(t)
	up := &coreUpstream{fixture: f, earlyMissing: true, unavailable: true}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := New(Config{Mode: "REQ"}, db, up)
	p := Platform{QEID: "Q", PCEID: "0000", PlatformManifest: "abcdef"}
	if _, err = s.fetchPlatform(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if up.manifest != p.PlatformManifest {
		t.Fatal("manifest lost")
	}
	_ = db.View(func(tx *store.Tx) error {
		keys := tx.Keys(registrationBucket)
		if len(keys) != 1 {
			t.Fatal("unavailable TCB not queued")
		}
		var registration registrationRecord
		_, err := tx.Get(registrationBucket, keys[0], &registration)
		if err != nil {
			return err
		}
		if registration.State != "reg_na" || registration.Platform.PCESVN != "0200" {
			t.Fatal("wrong unavailable TCB")
		}
		return nil
	})
}

func TestCoreAllUnavailableKeepsREQQueue(t *testing.T) {
	f := newCoreFixture(t)
	up := &coreUpstream{fixture: f, allUnavailable: true}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := New(Config{Mode: "REQ"}, db, up)
	_, err = s.fetchPlatform(context.Background(), Platform{QEID: "Q", PCEID: "0000", PlatformManifest: "manifest"})
	requireCoreStatus(t, err, 404)
	if err = db.View(func(tx *store.Tx) error {
		if len(tx.Keys(platformBucket)) != 0 || len(tx.Keys(collateralBucket)) != 0 {
			t.Fatal("unavailable collateral persisted")
		}
		if len(tx.Keys(registrationBucket)) != 1 {
			t.Fatal("missing unavailable registration")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCoreTrustPinAndUpstreamFailure(t *testing.T) {
	f := newCoreFixture(t)
	other := newCoreFixture(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(other.rootPEM))
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	up := &coreUpstream{fixture: f}
	s, _ := New(Config{Roots: pool}, db, up)
	_, err = s.Get(context.Background(), "sgx", "pckcert", coreQuery())
	requireCoreStatus(t, err, 460)
	up.fail = true
	_, err = s.Get(context.Background(), "sgx", "tcb", url.Values{"fmspc": {"001122334455"}})
	requireCoreStatus(t, err, 502)
}

type blockingCoreUpstream struct {
	*coreUpstream
	started chan struct{}
	release chan struct{}
}

func (u *blockingCoreUpstream) Fetch(ctx context.Context, product, endpoint string, q url.Values) (pcs.Response, error) {
	close(u.started)
	select {
	case <-u.release:
	case <-ctx.Done():
		return pcs.Response{}, ctx.Err()
	}
	return u.coreUpstream.Fetch(ctx, product, endpoint, q)
}

func TestCoreCacheHitsAndCancellationDuringBlockedFetch(t *testing.T) {
	f := newCoreFixture(t)
	up := &coreUpstream{fixture: f}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := New(Config{}, db, up)
	if _, err = s.Get(context.Background(), "sgx", "pckcert", coreQuery()); err != nil {
		t.Fatal(err)
	}
	blocked := &blockingCoreUpstream{coreUpstream: up, started: make(chan struct{}), release: make(chan struct{})}
	s.upstream = blocked
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocked.release) }) }
	defer release()
	fillDone := make(chan error, 1)
	go func() { _, err := s.Get(context.Background(), "sgx", "qve/identity", nil); fillDone <- err }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("cache fill did not start")
	}
	for _, endpoint := range []string{"tcb", "pckcert"} {
		q := url.Values{"fmspc": {"001122334455"}}
		if endpoint == "pckcert" {
			q = coreQuery()
		}
		done := make(chan error, 1)
		go func() { _, err := s.Get(context.Background(), "sgx", endpoint, q); done <- err }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s cache hit waited for upstream", endpoint)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	q := coreQuery()
	q.Set("cpusvn", strings.Repeat("03", 16))
	cancelDone := make(chan error, 1)
	go func() { _, err := s.Get(ctx, "sgx", "pckcert", q); cancelDone <- err }()
	select {
	case err := <-cancelDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("canceled wait: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled cache miss waited for upstream")
	}
	release()
	select {
	case err := <-fillDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cache fill did not finish")
	}
}
