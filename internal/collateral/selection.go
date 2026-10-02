// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause
// PCK selection is translated from service/pckCertSelection/pckCertSelection.js.

package collateral

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNoCertificate means no PCK certificate has a TCB supported by the platform.
var ErrNoCertificate = errors.New("no certificate found for given platform")

// PCKCertificate stores a certificate and its Intel TCBM identifier.
type PCKCertificate struct {
	TCBM string `json:"tcbm"`
	Cert string `json:"pck_cert"`
}

// SelectBestPCKCert implements the PCCS type-0 Intel PCK selection algorithm.
// Raw PCESVN is hexadecimal little-endian. TCBInfoJSON may be a payload or
// signed envelope. Certificates must share PCEID, FMSPC, and PPID. This function
// parses metadata but does not authenticate inputs or check their expiration.
// Certificates outside published TCB levels remain eligible in a final bucket,
// preserving PCCS behavior for older platform TCBs.
func SelectBestPCKCert(rawCPUSVN, rawPCESVN, pceID string, certs []PCKCertificate, tcbInfoJSON []byte) (PCKCertificate, error) {
	raw, err := ParseTCB(rawCPUSVN, rawPCESVN)
	if err != nil {
		return PCKCertificate{}, err
	}
	if _, err := decodeHex(pceID, 2, "PCEID"); err != nil {
		return PCKCertificate{}, err
	}
	info, err := ParseTCBInfo(tcbInfoJSON)
	if err != nil {
		return PCKCertificate{}, err
	}
	if !strings.EqualFold(info.PCEID, pceID) {
		return PCKCertificate{}, errors.New("TCB info PCEID differs from platform PCEID")
	}
	type parsedCert struct {
		source PCKCertificate
		tcb    TCB
	}
	type bucket struct {
		tcb   TCB
		certs []parsedCert
	}
	buckets := make([]bucket, 0, len(info.Levels)+1)
	// Stable insertion preserves source order when adjacent levels are not
	// comparable. A total-order sorter cannot express the TCB partial order.
	for _, level := range info.Levels {
		index := len(buckets)
		for index > 0 {
			comparison, err := level.Compare(buckets[index-1].tcb)
			if err != nil || comparison <= 0 {
				break
			}
			index--
		}
		buckets = append(buckets, bucket{})
		copy(buckets[index+1:], buckets[index:])
		buckets[index] = bucket{tcb: level}
	}
	var unmatched []parsedCert
	var ppid string
	for i, cert := range certs {
		parsed, err := ParsePCKCertificate([]byte(cert.Cert))
		if err != nil {
			return PCKCertificate{}, fmt.Errorf("PCK certificate %d: %w", i, err)
		}
		if !strings.EqualFold(parsed.PCEID, pceID) {
			return PCKCertificate{}, errors.New("PCK certificate PCEID differs from platform PCEID")
		}
		if !strings.EqualFold(parsed.FMSPC, info.FMSPC) {
			return PCKCertificate{}, errors.New("PCK certificate FMSPC differs from TCB info FMSPC")
		}
		if i == 0 {
			ppid = parsed.PPID
		} else if ppid != parsed.PPID {
			return PCKCertificate{}, errors.New("PCK certificate PPIDs differ")
		}
		if cert.TCBM == "" {
			cert.TCBM = parsed.TCB.TCBM()
		} else if !strings.EqualFold(cert.TCBM, parsed.TCB.TCBM()) {
			return PCKCertificate{}, errors.New("PCK certificate TCBM differs from its SGX extension")
		}
		cert.TCBM = strings.ToUpper(cert.TCBM)
		item := parsedCert{source: cert, tcb: parsed.TCB}
		placed := false
		for j := range buckets {
			comparison, err := item.tcb.Compare(buckets[j].tcb)
			if err != nil || comparison < 0 {
				continue
			}
			index := len(buckets[j].certs)
			for k, existing := range buckets[j].certs {
				comparison, err := item.tcb.Compare(existing.tcb)
				if err == nil && comparison >= 0 {
					index = k
					break
				}
			}
			buckets[j].certs = append(buckets[j].certs, parsedCert{})
			copy(buckets[j].certs[index+1:], buckets[j].certs[index:])
			buckets[j].certs[index] = item
			placed = true
			break
		}
		if !placed {
			unmatched = append(unmatched, item)
		}
	}
	buckets = append(buckets, bucket{certs: unmatched})
	for _, bucket := range buckets {
		for _, cert := range bucket.certs {
			comparison, err := raw.Compare(cert.tcb)
			if err == nil && comparison >= 0 {
				return cert.source, nil
			}
		}
	}
	return PCKCertificate{}, ErrNoCertificate
}
