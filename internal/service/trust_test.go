// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package service

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/toratako/pccs-go/internal/store"
)

func TestConfiguredRootsApplyToExistingCache(t *testing.T) {
	fixture := newCoreFixture(t)
	upstream := &coreUpstream{fixture: fixture}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(Config{}, db, upstream)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), "sgx", "pckcert", coreQuery()); err != nil {
		t.Fatal(err)
	}
	calls := upstream.calls
	other := newCoreFixture(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(other.rootPEM))
	if _, err := New(Config{Mode: "OFFLINE", Roots: roots}, db, nil); err == nil {
		t.Fatal("existing cache must satisfy newly configured trust roots")
	}
	roots = x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(fixture.rootPEM))
	trusted, err := New(Config{Mode: "OFFLINE", Roots: roots}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.Get(context.Background(), "sgx", "pckcert", coreQuery()); err != nil {
		t.Fatal(err)
	}
	if upstream.calls != calls {
		t.Fatal("startup trust validation contacted PCS")
	}
}

func TestPinnedCRLRequiresAnAuthenticatedIssuer(t *testing.T) {
	fixture := newCoreFixture(t)
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(fixture.rootPEM))
	s, err := New(Config{Mode: "OFFLINE", Roots: roots}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{Body: fixture.rootCRL, Header: make(http.Header)}
	_, err = s.validateCollateral("sgx", "crl", nil, response)
	requireCoreStatus(t, err, 460)
	response.Header.Set(pckCRLChainHeader, fixture.signingChain)
	if _, err = s.validateCollateral("sgx", "crl", nil, response); err != nil {
		t.Fatalf("authenticated root CRL rejected: %v", err)
	}
}

func TestPinnedStartupChecksStoredRevocations(t *testing.T) {
	fixture := newCoreFixture(t)
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(Config{}, db, &coreUpstream{fixture: fixture})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), "sgx", "pckcert", coreQuery()); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *store.Tx) error {
		return putCollateral(tx, "sgx", "pckcrl", url.Values{"ca": {"processor"}}, Response{
			Body: fixture.makeRevokedCRL(false, 4), Header: fixture.pckCRL.Header,
		})
	}); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(fixture.rootPEM))
	if _, err := New(Config{Mode: "OFFLINE", Roots: roots}, db, nil); err == nil {
		t.Fatal("startup accepted a certificate revoked by the stored issuer CRL")
	}
}
