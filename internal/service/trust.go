// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package service

import (
	"crypto/x509"

	"github.com/toratako/pccs-go/internal/collateral"
	"github.com/toratako/pccs-go/internal/store"
)

// A changed trust configuration also applies to persisted data. Validate before
// accepting traffic, without modifying the snapshot or contacting upstream PCS.
func (s *Service) validatePinnedCache() error {
	var entries []cacheEntry
	var platforms []platformRecord
	if err := s.db.View(func(tx *store.Tx) error {
		for _, key := range tx.Keys(collateralBucket) {
			var entry cacheEntry
			if _, err := tx.Get(collateralBucket, key, &entry); err != nil {
				return err
			}
			entries = append(entries, entry)
		}
		for _, key := range tx.Keys(platformBucket) {
			var platform platformRecord
			if _, err := tx.Get(platformBucket, key, &platform); err != nil {
				return err
			}
			platforms = append(platforms, platform)
		}
		return nil
	}); err != nil {
		return err
	}
	var certs []*x509.Certificate
	var crls []*x509.RevocationList
	for _, entry := range entries {
		if _, err := s.validateCollateral(entry.Product, entry.Endpoint, entry.Query, entry.Response); err != nil {
			return err
		}
		for _, header := range []string{pckCRLChainHeader, tcbChainHeader, identityChainHeader, pckChainHeader} {
			if chain := entry.Response.Header.Get(header); chain != "" {
				parsed, err := collateral.ParseCertificates([]byte(chain))
				if err != nil {
					return err
				}
				certs = append(certs, parsed...)
			}
		}
		if entry.Endpoint == "pckcrl" || entry.Endpoint == "rootcacrl" || entry.Endpoint == "crl" {
			crl, err := collateral.ParseCRL(entry.Response.Body)
			if err != nil {
				return err
			}
			crls = append(crls, crl)
		}
	}
	for _, platform := range platforms {
		if err := s.validatePlatformRecord(&platform); err != nil {
			return err
		}
		chain, err := collateral.ParseCertificates([]byte(platform.IssuerChain))
		if err != nil {
			return err
		}
		certs = append(certs, chain...)
		for _, pck := range platform.Certificates {
			parsed, err := collateral.ParsePCKCertificate([]byte(pck.Cert))
			if err != nil {
				return err
			}
			certs = append(certs, parsed.Certificate)
		}
	}
	for _, cert := range certs {
		if err := checkImportRevocation(cert, certs, crls); err != nil {
			return err
		}
	}
	return nil
}
