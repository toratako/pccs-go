// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2011-2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package collateral

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var sgxOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}

// PCKInfo contains the Intel SGX extension values from a PCK certificate.
// Hexadecimal fields use uppercase. CA is PROCESSOR or PLATFORM when recognized.
type PCKInfo struct {
	Certificate *x509.Certificate
	FMSPC       string
	PCEID       string
	PPID        string
	CA          string
	TCB         TCB
}

// ParseCertificates accepts a PEM chain, URI-escaped PEM chain, or one DER
// certificate. It rejects non-certificate blocks and trailing non-whitespace.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	// DER may end in a byte that is whitespace in ASCII; never trim it.
	if len(data) > 0 && data[0] == 0x30 {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return []*x509.Certificate{cert}, nil
	}
	data = bytes.TrimSpace(data)
	if bytes.HasPrefix(data, []byte("-----BEGIN%20")) || bytes.HasPrefix(data, []byte("%2D%2D")) || bytes.HasPrefix(data, []byte("%2d%2d")) {
		decoded, err := url.PathUnescape(string(data))
		if err != nil {
			return nil, fmt.Errorf("decode issuer chain: %w", err)
		}
		data = bytes.TrimSpace([]byte(decoded))
	}
	if !bytes.HasPrefix(data, []byte("-----BEGIN")) {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return []*x509.Certificate{cert}, nil
	}
	var certs []*x509.Certificate
	for len(data) > 0 {
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("unexpected data in certificate chain")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate PEM")
		}
		// pem.Decode can skip a malformed first block and find a later one.
		// Reject such input rather than silently dropping a certificate.
		if bytes.Count(data[:len(data)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return nil, errors.New("malformed certificate PEM before valid block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
		data = bytes.TrimSpace(rest)
	}
	if len(certs) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	return certs, nil
}

// ParsePCKCertificate reads exactly one v3 PCK certificate and its SGX
// extensions by OID, independent of ASN.1 sequence order. It validates that
// component versions agree with the certificate CPUSVN octet string.
// Parsing does not verify the certificate's issuer, validity, or signature.
func ParsePCKCertificate(data []byte) (*PCKInfo, error) {
	certs, err := ParseCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, errors.New("expected exactly one PCK certificate")
	}
	cert := certs[0]
	if cert.Version != 3 {
		return nil, fmt.Errorf("PCK certificate must be version 3, got %d", cert.Version)
	}
	info := &PCKInfo{Certificate: cert}
	switch {
	case strings.Contains(cert.Issuer.CommonName, "Platform"):
		info.CA = "PLATFORM"
	case strings.Contains(cert.Issuer.CommonName, "Processor"):
		info.CA = "PROCESSOR"
	}
	var extension []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sgxOID) {
			if extension != nil {
				return nil, errors.New("duplicate SGX extension")
			}
			extension = ext.Value
		}
	}
	if extension == nil {
		return nil, errors.New("PCK certificate has no SGX extension")
	}
	values, err := parseExtensionEntries(extension)
	if err != nil {
		return nil, fmt.Errorf("parse SGX extension: %w", err)
	}
	for _, item := range []struct {
		suffix string
		size   int
		target *string
	}{
		{".1", 16, &info.PPID}, {".3", 2, &info.PCEID}, {".4", 6, &info.FMSPC},
	} {
		var value []byte
		raw, ok := values[sgxOID.String()+item.suffix]
		if !ok {
			return nil, fmt.Errorf("SGX extension missing %s", item.suffix)
		}
		if err := unmarshalDER(raw.FullBytes, &value); err != nil || len(value) != item.size {
			return nil, fmt.Errorf("invalid SGX extension %s", item.suffix)
		}
		*item.target = strings.ToUpper(hex.EncodeToString(value))
	}
	tcbRaw, ok := values[sgxOID.String()+".2"]
	if !ok {
		return nil, errors.New("SGX extension missing TCB")
	}
	tcbValues, err := parseExtensionEntries(tcbRaw.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("parse SGX TCB: %w", err)
	}
	var cpu []byte
	if err := unmarshalDER(tcbValues[sgxOID.String()+".2.18"].FullBytes, &cpu); err != nil || len(cpu) != 16 {
		return nil, errors.New("invalid SGX TCB CPUSVN")
	}
	copy(info.TCB.CPUSVN[:], cpu)
	pce, err := extensionInteger(tcbValues, sgxOID.String()+".2.17", 65535)
	if err != nil {
		return nil, err
	}
	info.TCB.PCESVN = uint16(pce)
	for i, component := range info.TCB.CPUSVN {
		v, err := extensionInteger(tcbValues, fmt.Sprintf("%s.2.%d", sgxOID.String(), i+1), 255)
		if err != nil {
			return nil, err
		}
		if byte(v) != component {
			return nil, fmt.Errorf("SGX TCB component %d disagrees with CPUSVN", i+1)
		}
	}
	return info, nil
}

func extensionInteger(values map[string]asn1.RawValue, oid string, max int) (int, error) {
	var v int
	if err := unmarshalDER(values[oid].FullBytes, &v); err != nil || v < 0 || v > max {
		return 0, fmt.Errorf("invalid SGX integer %s", oid)
	}
	return v, nil
}

func parseExtensionEntries(der []byte) (map[string]asn1.RawValue, error) {
	var sequence []asn1.RawValue
	if err := unmarshalDER(der, &sequence); err != nil {
		return nil, err
	}
	values := make(map[string]asn1.RawValue, len(sequence))
	for _, raw := range sequence {
		var entry struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if err := unmarshalDER(raw.FullBytes, &entry); err != nil {
			return nil, err
		}
		key := entry.OID.String()
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("duplicate SGX OID %s", key)
		}
		values[key] = entry.Value
	}
	return values, nil
}

func unmarshalDER(der []byte, value any) error {
	rest, err := asn1.Unmarshal(der, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing ASN.1 data")
	}
	return nil
}

// VerifyCertificateChain verifies a leaf against explicit trusted roots and
// supplied intermediates at now. Certificates in issuerChain are never added
// as trust anchors. A zero now uses the current time. Revocation is separate.
func VerifyCertificateChain(leaf *x509.Certificate, issuerChain []byte, roots *x509.CertPool, now time.Time) error {
	if leaf == nil {
		return errors.New("missing leaf certificate")
	}
	if roots == nil || len(roots.Subjects()) == 0 {
		return errors.New("a nonempty explicit trust store is required")
	}
	certs, err := ParseCertificates(issuerChain)
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("verify certificate chain: %w", err)
	}
	return nil
}
