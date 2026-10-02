// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package collateral

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"
)

func makeSGXCertificate(t *testing.T, mutate func([]asn1.RawValue) []asn1.RawValue) []byte {
	t.Helper()
	entry := func(suffix string, value any) asn1.RawValue {
		oid := append(asn1.ObjectIdentifier{}, sgxOID...)
		for _, v := range suffix {
			if v >= '0' && v <= '9' {
				oid = append(oid, int(v-'0'))
			}
		}
		der, err := asn1.Marshal(struct {
			OID   asn1.ObjectIdentifier
			Value any
		}{oid, value})
		if err != nil {
			t.Fatal(err)
		}
		return asn1.RawValue{FullBytes: der}
	}
	var tcbValues []asn1.RawValue
	for i := 1; i <= 16; i++ {
		oid := append(append(asn1.ObjectIdentifier{}, sgxOID...), 2, i)
		der, err := asn1.Marshal(struct {
			OID   asn1.ObjectIdentifier
			Value int
		}{oid, i})
		if err != nil {
			t.Fatal(err)
		}
		tcbValues = append(tcbValues, asn1.RawValue{FullBytes: der})
	}
	for i, value := range []any{513, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}} {
		oid := append(append(asn1.ObjectIdentifier{}, sgxOID...), 2, 17+i)
		der, err := asn1.Marshal(struct {
			OID   asn1.ObjectIdentifier
			Value any
		}{oid, value})
		if err != nil {
			t.Fatal(err)
		}
		tcbValues = append(tcbValues, asn1.RawValue{FullBytes: der})
	}
	// Reordered entries exercise OID lookup rather than array indexing.
	slices.Reverse(tcbValues)
	values := []asn1.RawValue{entry("4", []byte{1, 2, 3, 4, 5, 6}), entry("3", []byte{0, 0}), entry("2", tcbValues), entry("1", make([]byte, 16))}
	if mutate != nil {
		values = mutate(values)
	}
	extension, err := asn1.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Intel SGX PCK Processor CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: sgxOID, Value: extension}}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSGXExtensionsAreParsedByOID(t *testing.T) {
	pemCert := makeSGXCertificate(t, nil)
	info, err := ParsePCKCertificate(pemCert)
	if err != nil {
		t.Fatal(err)
	}
	if info.FMSPC != "010203040506" || info.PCEID != "0000" || info.PPID != "00000000000000000000000000000000" || info.CA != "PROCESSOR" {
		t.Fatalf("wrong extensions: %#v", info)
	}
	if info.TCB.PCESVN != 513 || info.TCB.CPUSVN[15] != 16 {
		t.Fatalf("wrong TCB: %#v", info.TCB)
	}
	if _, err := ParsePCKCertificate(append(pemCert, pemCert...)); err == nil {
		t.Fatal("accepted multiple PCK certificates")
	}
	if _, err := ParsePCKCertificate(makeSGXCertificate(t, func(v []asn1.RawValue) []asn1.RawValue { return append(v, v[0]) })); err == nil {
		t.Fatal("accepted duplicate SGX OID")
	}
	if _, err := ParsePCKCertificate(makeSGXCertificate(t, func(v []asn1.RawValue) []asn1.RawValue { return v[:3] })); err == nil {
		t.Fatal("accepted missing PPID")
	}
	if _, err := ParsePCKCertificate(makeSGXCertificate(t, func(v []asn1.RawValue) []asn1.RawValue {
		var tcbs struct {
			OID   asn1.ObjectIdentifier
			Value []asn1.RawValue
		}
		if _, err := asn1.Unmarshal(v[2].FullBytes, &tcbs); err != nil {
			t.Fatal(err)
		}
		// Reversed TCB sequence puts CPUSVN first. Change its final component.
		var cpu struct {
			OID   asn1.ObjectIdentifier
			Value []byte
		}
		if _, err := asn1.Unmarshal(tcbs.Value[0].FullBytes, &cpu); err != nil {
			t.Fatal(err)
		}
		cpu.Value[15]++
		der, err := asn1.Marshal(cpu)
		if err != nil {
			t.Fatal(err)
		}
		tcbs.Value[0] = asn1.RawValue{FullBytes: der}
		der, err = asn1.Marshal(tcbs)
		if err != nil {
			t.Fatal(err)
		}
		v[2] = asn1.RawValue{FullBytes: der}
		return v
	})); err == nil {
		t.Fatal("accepted inconsistent CPUSVN components")
	}
}
