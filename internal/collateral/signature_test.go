// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package collateral

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"
)

type testPKI struct {
	root, intermediate, signer          *x509.Certificate
	rootKey, intermediateKey, signerKey *ecdsa.PrivateKey
	chain                               []byte
	roots                               *x509.CertPool
	now                                 time.Time
}

func makeTestPKI(t *testing.T) testPKI {
	t.Helper()
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	p := testPKI{now: now, roots: x509.NewCertPool()}
	create := func(serial int64, name string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature}
		if isCA {
			template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		if parent == nil {
			parent, parentKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	p.root, p.rootKey = create(1, "test root", true, nil, nil)
	p.intermediate, p.intermediateKey = create(2, "test intermediate", true, p.root, p.rootKey)
	p.signer, p.signerKey = create(3, "test signer", false, p.intermediate, p.intermediateKey)
	p.roots.AddCert(p.root)
	for _, cert := range []*x509.Certificate{p.signer, p.intermediate, p.root} {
		p.chain = append(p.chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return p
}

func signEnvelope(t *testing.T, payload, field string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(compact.Bytes())
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return []byte(fmt.Sprintf(`{"%s":%s,"signature":"%s"}`, field, payload, hex.EncodeToString(signature)))
}

func TestVerifySignedJSON(t *testing.T) {
	p := makeTestPKI(t)
	payload := `{ "id": "SGX", "issueDate":"2026-10-02T00:00:00Z", "nextUpdate":"2026-10-04T00:00:00Z" }`
	for _, field := range []string{"tcbInfo", "enclaveIdentity"} {
		document := signEnvelope(t, payload, field, p.signerKey)
		got, err := VerifySignedJSON(document, field, p.chain, p.roots, p.now)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != payload {
			t.Fatalf("payload bytes changed: %s", got)
		}
		if err := VerifyFreshness(got, p.now); err != nil {
			t.Fatal(err)
		}
		tampered := bytes.Replace(document, []byte("SGX"), []byte("TDX"), 1)
		if _, err := VerifySignedJSON(tampered, field, p.chain, p.roots, p.now); err == nil {
			t.Fatal("accepted tampered payload")
		}
		changedSpace := bytes.Replace(document, []byte(`{ "id"`), []byte(`{"id"`), 1)
		if _, err := VerifySignedJSON(changedSpace, field, p.chain, p.roots, p.now); err != nil {
			t.Fatalf("rejected insignificant JSON whitespace change: %v", err)
		}
		changedStringSpace := bytes.Replace(document, []byte(`"SGX"`), []byte(`"SG X"`), 1)
		if _, err := VerifySignedJSON(changedStringSpace, field, p.chain, p.roots, p.now); err == nil {
			t.Fatal("accepted whitespace change within a string")
		}
		if _, err := VerifySignedJSON(document, field, p.chain, nil, p.now); err == nil {
			t.Fatal("trusted supplied chain without roots")
		}
		if _, err := VerifySignedJSON(document, field, p.chain, p.roots, p.now.Add(2*time.Hour)); err == nil {
			t.Fatal("accepted expired signer")
		}
		untrusted := makeTestPKI(t)
		if _, err := VerifySignedJSON(document, field, p.chain, untrusted.roots, p.now); err == nil {
			t.Fatal("accepted untrusted root")
		}
		if _, err := VerifySignedJSON(document, field, []byte(url.PathEscape(string(p.chain))), p.roots, p.now); err != nil {
			t.Fatalf("URI escaped chain: %v", err)
		}
	}
	duplicate := signEnvelope(t, `{"id":"SGX","id":"TDX"}`, "tcbInfo", p.signerKey)
	if _, err := VerifySignedJSON(duplicate, "tcbInfo", p.chain, p.roots, p.now); err == nil {
		t.Fatal("accepted duplicate payload key")
	}
	duplicateEnvelope := bytes.Replace(signEnvelope(t, payload, "tcbInfo", p.signerKey), []byte(`{"tcbInfo":`), []byte(`{"signature":"00","tcbInfo":`), 1)
	if _, err := VerifySignedJSON(duplicateEnvelope, "tcbInfo", p.chain, p.roots, p.now); err == nil {
		t.Fatal("accepted duplicate envelope key")
	}
}

func TestFreshnessBounds(t *testing.T) {
	payload := []byte(`{"issueDate":"2026-10-02T00:00:00Z","nextUpdate":"2026-10-04T00:00:00Z"}`)
	for _, now := range []time.Time{time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)} {
		if err := VerifyFreshness(payload, now); err == nil {
			t.Fatal("accepted collateral outside validity interval")
		}
	}
	if err := VerifyFreshness([]byte(`{}`), time.Now()); err == nil {
		t.Fatal("accepted missing dates")
	}
}

func TestCertificateAndCRLVerification(t *testing.T) {
	p := makeTestPKI(t)
	if err := VerifyCertificateChain(p.signer, p.chain, p.roots, p.now); err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertificates(p.signer.Raw)
	if err != nil || len(certs) != 1 {
		t.Fatalf("DER parse: %v", err)
	}
	if _, err := ParseCertificates(append(p.chain, []byte("garbage")...)); err == nil {
		t.Fatal("accepted trailing certificate data")
	}
	if _, err := ParseCertificates(append([]byte("garbage"), p.chain...)); err == nil {
		t.Fatal("accepted leading certificate data")
	}
	if _, err := ParseCertificates(append([]byte("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----\n"), p.chain...)); err == nil {
		t.Fatal("silently skipped malformed first certificate")
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: p.now.Add(-time.Minute), NextUpdate: p.now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: p.signer.SerialNumber, RevocationTime: p.now.Add(-time.Minute)}}}, p.intermediate, p.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{der, []byte(hex.EncodeToString(der)), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})} {
		crl, err := ParseCRL(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCRL(crl, p.intermediate, p.now); err != nil {
			t.Fatal(err)
		}
		if !IsRevoked(crl, p.signer.SerialNumber) || IsRevoked(crl, big.NewInt(99)) {
			t.Fatal("incorrect revoked serial lookup")
		}
		if err := VerifyCRL(crl, p.root, p.now); err == nil {
			t.Fatal("accepted wrong CRL issuer")
		}
		if err := VerifyCRL(crl, p.intermediate, p.now.Add(time.Hour)); err == nil {
			t.Fatal("accepted expired CRL")
		}
	}
}
