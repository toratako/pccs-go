// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package collateral

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func fixtureCertificates(t *testing.T) []PCKCertificate {
	t.Helper()
	b, err := os.ReadFile("testdata/pck_certificates.json")
	if err != nil {
		t.Fatal(err)
	}
	var certs []PCKCertificate
	if err := json.Unmarshal(b, &certs); err != nil {
		t.Fatal(err)
	}
	return certs
}

func fixtureTCBInfo(t *testing.T) []byte {
	t.Helper()
	tcbs := []struct {
		CPU string
		PCE string
	}{
		{"04040202040100030000000000000000", "0B00"},
		{"03030202040100030000000000000000", "0B00"},
		{"02020202030100030000000000000000", "0500"},
		{"01010202010100030000000000000000", "0400"},
	}
	levels := []any{}
	for _, raw := range tcbs {
		tcb, err := ParseTCB(raw.CPU, raw.PCE)
		if err != nil {
			t.Fatal(err)
		}
		components := []any{}
		for _, v := range tcb.CPUSVN {
			components = append(components, map[string]any{"svn": v})
		}
		levels = append(levels, map[string]any{"tcb": map[string]any{"sgxtcbcomponents": components, "pcesvn": tcb.PCESVN}})
	}
	b, err := json.Marshal(map[string]any{"pceId": "0000", "fmspc": "123456780000", "tcbType": 0, "tcbLevels": levels})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTCBPartialOrderAndLittleEndian(t *testing.T) {
	a, err := ParseTCB("01011111000100000000000000000000", "0102")
	if err != nil {
		t.Fatal(err)
	}
	if a.PCESVN != 513 {
		t.Fatalf("PCESVN = %d, want 513", a.PCESVN)
	}
	if a.TCBM() != "010111110001000000000000000000000102" {
		t.Fatal(a.TCBM())
	}
	b := a
	b.CPUSVN[0]++
	b.PCESVN--
	if _, err := a.Compare(b); !errors.Is(err, ErrNonComparable) {
		t.Fatalf("mixed versions: %v", err)
	}
	b.PCESVN = a.PCESVN
	if v, err := a.Compare(b); err != nil || v != -1 {
		t.Fatalf("lower: %d, %v", v, err)
	}
	if v, err := b.Compare(a); err != nil || v != 1 {
		t.Fatalf("higher: %d, %v", v, err)
	}
	if v, err := a.Compare(a); err != nil || v != 0 {
		t.Fatalf("equal: %d, %v", v, err)
	}
	for _, raw := range []struct{ cpu, pce string }{{"01", "0000"}, {"GG011111000100000000000000000000", "0000"}, {"01011111000100000000000000000000", "0"}, {"01011111000100000000000000000000", "ZZZZ"}} {
		if _, err := ParseTCB(raw.cpu, raw.pce); err == nil {
			t.Fatalf("accepted invalid TCB %v", raw)
		}
	}
}

func TestSelectionOriginalJavaScriptFixtures(t *testing.T) {
	certs, info := fixtureCertificates(t), fixtureTCBInfo(t)
	cases := []struct{ name, cpu, pce, want string }{
		{"highest exact", "04040202040100070000000000000000", "0B00", "040402020401000700000000000000000B00"},
		{"middle exact", "03030202040100030000000000000000", "0B00", "030302020401000300000000000000000B00"},
		{"middle between", "03040202040100030000000000000000", "0B00", "030302020401000300000000000000000B00"},
		{"minimum", "02020202030100030000000000000000", "0500", "020202020301000300000000000000000500"},
		{"higher PCE", "02020202030100030000000000000000", "0F00", "020202020301000300000000000000000B00"},
		{"incomparable candidates", "04040202040100070000000000000000", "0500", "020202020301000500000000000000000500"},
		{"between PCEs", "03030202040100050000000000000000", "0C00", "030302020401000500000000000000000B00"},
		{"above all", "05050505050500070000000000000000", "0F00", "040402020401000700000000000000000B00"},
		{"unpublished TCB", "0202020203010003000000000000000F", "0400", "0202020203010003000000000000000F0100"},
		{"lowercase", "0303020f040100030000000000000000", "0b00", "030302020401000300000000000000000B00"},
		{"below CPU", "02020202030100020000000000000000", "0500", ""},
		{"below PCE", "02020202030100030000000000000000", "0400", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectBestPCKCert(tc.cpu, tc.pce, "0000", certs, info)
			if tc.want == "" {
				if !errors.Is(err, ErrNoCertificate) {
					t.Fatalf("want no certificate, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.TCBM != tc.want {
				t.Fatalf("got %s, want %s", got.TCBM, tc.want)
			}
		})
	}
	for i, j := 0, len(certs)-1; i < j; i, j = i+1, j-1 {
		certs[i], certs[j] = certs[j], certs[i]
	}
	got, err := SelectBestPCKCert("03040202040100050000000000000000", "0F00", "0000", certs, info)
	if err != nil || got.TCBM != "030302020401000500000000000000000B00" {
		t.Fatalf("reversed input: %s %v", got.TCBM, err)
	}
}

func TestSelectionRejectsMismatchedMetadata(t *testing.T) {
	certs, info := fixtureCertificates(t), fixtureTCBInfo(t)
	if _, err := SelectBestPCKCert("03040202040100050000000000000000", "0F00", "AAAA", certs, info); err == nil {
		t.Fatal("accepted mismatched PCEID")
	}
	certs[0].TCBM = "000000000000000000000000000000000000"
	if _, err := SelectBestPCKCert("03040202040100050000000000000000", "0F00", "0000", certs, info); err == nil {
		t.Fatal("accepted mismatched TCBM")
	}
	if _, err := SelectBestPCKCert("03040202040100050000000000000000", "0F00", "0000", nil, info); !errors.Is(err, ErrNoCertificate) {
		t.Fatal(err)
	}
}

func TestTCBInfoRejectsInvalidAndSupportsV2(t *testing.T) {
	legacy := map[string]any{"pcesvn": 513}
	for i := 1; i <= 16; i++ {
		legacy[legacyName(i)] = i
	}
	b, _ := json.Marshal(map[string]any{"fmspc": "123456780000", "pceId": "0000", "tcbType": 0, "tcbLevels": []any{map[string]any{"tcb": legacy}}})
	info, err := ParseTCBInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.Levels[0].PCESVN != 513 || info.Levels[0].CPUSVN[15] != 16 {
		t.Fatalf("unexpected v2 TCB: %#v", info.Levels[0])
	}
	for _, data := range []string{`{"tcbType":0,"tcbType":1}`, `null`, `[]`, `{}`, `{"fmspc":"123456780000","pceId":"0000","tcbType":0,"tcbLevels":[]}`} {
		if _, err := ParseTCBInfo([]byte(data)); err == nil {
			t.Fatalf("accepted invalid TCB info %s", data)
		}
	}
}

func legacyName(i int) string {
	const digits = "0123456789"
	return "sgxtcbcomp" + string([]byte{digits[i/10], digits[i%10]}) + "svn"
}
