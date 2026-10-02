// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2011-2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package collateral

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

// VerifySignedJSON authenticates an Intel tcbInfo or enclaveIdentity envelope.
// The first certificate in issuerChain must be the signing certificate; its
// chain is verified against roots. Intel signatures contain 32-byte big-endian
// r followed by 32-byte big-endian s, encoded as 128 hexadecimal characters.
// Intel signs the payload without insignificant JSON whitespace. Compaction
// preserves field order, number spelling, escapes, and whitespace in strings.
// The returned payload retains its original bytes for the caller to consume.
// Duplicate JSON keys are rejected to avoid divergent parsing by consumers.
// Payload freshness and identity matching are caller policy, not signature
// validation; VerifyFreshness can enforce Intel issueDate/nextUpdate bounds.
func VerifySignedJSON(document []byte, field string, issuerChain []byte, roots *x509.CertPool, now time.Time) (json.RawMessage, error) {
	if field != "tcbInfo" && field != "enclaveIdentity" {
		return nil, errors.New("unsupported signed collateral field")
	}
	if err := validateJSON(document); err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(document, &envelope); err != nil {
		return nil, err
	}
	payload, ok := envelope[field]
	if !ok || len(payload) == 0 || payload[0] != '{' {
		return nil, fmt.Errorf("missing or invalid %s object", field)
	}
	var signatureHex string
	if err := json.Unmarshal(envelope["signature"], &signatureHex); err != nil {
		return nil, fmt.Errorf("invalid collateral signature: %w", err)
	}
	signature, err := decodeHex(signatureHex, 64, "signature")
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertificates(issuerChain)
	if err != nil {
		return nil, err
	}
	signer := certs[0]
	if err := VerifyCertificateChain(signer, issuerChain, roots, now); err != nil {
		return nil, err
	}
	if signer.IsCA || signer.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("collateral signer must be a non-CA certificate permitted to sign")
	}
	key, ok := signer.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("collateral signer must use ECDSA P-256")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, payload); err != nil {
		return nil, fmt.Errorf("invalid signed payload: %w", err)
	}
	digest := sha256.Sum256(compact.Bytes())
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, errors.New("invalid collateral signature")
	}
	return payload, nil
}

// VerifyFreshness requires issueDate <= now < nextUpdate on a signed payload.
// It should be called after VerifySignedJSON; it does not authenticate bytes.
func VerifyFreshness(payload []byte, now time.Time) error {
	var dates struct {
		IssueDate  time.Time `json:"issueDate"`
		NextUpdate time.Time `json:"nextUpdate"`
	}
	if err := json.Unmarshal(payload, &dates); err != nil {
		return fmt.Errorf("invalid collateral dates: %w", err)
	}
	if now.IsZero() {
		now = time.Now()
	}
	if dates.IssueDate.IsZero() || dates.NextUpdate.IsZero() || !dates.NextUpdate.After(dates.IssueDate) {
		return errors.New("invalid collateral validity interval")
	}
	if now.Before(dates.IssueDate) || !now.Before(dates.NextUpdate) {
		return errors.New("collateral is outside its validity interval")
	}
	return nil
}

// ParseCRL accepts DER, PEM, or hexadecimal DER, as used by Intel PCCS imports.
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		data = bytes.TrimSpace(data)
		block, rest := pem.Decode(data)
		if block == nil || (block.Type != "X509 CRL" && block.Type != "CRL") || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("invalid CRL PEM")
		}
		if bytes.Count(data[:len(data)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return nil, errors.New("malformed CRL PEM before valid block")
		}
		data = block.Bytes
	} else if len(data) > 0 && data[0] != 0x30 {
		decoded, err := hex.DecodeString(string(bytes.TrimSpace(data)))
		if err != nil {
			return nil, fmt.Errorf("invalid hexadecimal CRL: %w", err)
		}
		data = decoded
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}
	return crl, nil
}

// VerifyCRL checks the issuer signature and the CRL validity interval.
// The caller must authenticate issuer with VerifyCertificateChain first.
func VerifyCRL(crl *x509.RevocationList, issuer *x509.Certificate, now time.Time) error {
	if crl == nil || issuer == nil {
		return errors.New("missing CRL or issuer")
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("verify CRL signature: %w", err)
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return errors.New("CRL issuer name does not match certificate")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if crl.ThisUpdate.IsZero() || !crl.NextUpdate.After(crl.ThisUpdate) || now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
		return errors.New("CRL is outside its validity interval")
	}
	return nil
}

// IsRevoked reports whether a serial number is listed by a verified CRL.
func IsRevoked(crl *x509.RevocationList, serial *big.Int) bool {
	if crl == nil || serial == nil {
		return false
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

func validateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSON(decoder); err != nil {
		return fmt.Errorf("invalid collateral JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing collateral JSON data")
	}
	return nil
}

func consumeJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if err := consumeJSON(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeJSON(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
