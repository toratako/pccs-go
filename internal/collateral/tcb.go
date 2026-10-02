// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package collateral

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrNonComparable means that some TCB components are higher and others lower.
var ErrNonComparable = errors.New("TCBs are not comparable")

// TCB contains the sixteen component security versions and the PCE version.
// Component versions form a partial order; lexicographic comparison is invalid.
type TCB struct {
	CPUSVN [16]byte
	PCESVN uint16
}

// ParseTCB reads hexadecimal CPUSVN and a two-byte little-endian PCESVN,
// as represented in PCCS API requests and TCBM values.
func ParseTCB(cpuSVN, pceSVN string) (TCB, error) {
	var t TCB
	cpu, err := decodeHex(cpuSVN, 16, "CPUSVN")
	if err != nil {
		return t, err
	}
	pce, err := decodeHex(pceSVN, 2, "PCESVN")
	if err != nil {
		return t, err
	}
	copy(t.CPUSVN[:], cpu)
	t.PCESVN = binary.LittleEndian.Uint16(pce)
	return t, nil
}

// Compare returns -1, 0, or 1 for componentwise lower, equal, or higher TCBs.
// Incomparable TCBs return ErrNonComparable instead of an arbitrary ordering.
func (t TCB) Compare(other TCB) (int, error) {
	lower, higher := t.PCESVN < other.PCESVN, t.PCESVN > other.PCESVN
	for i, v := range t.CPUSVN {
		lower = lower || v < other.CPUSVN[i]
		higher = higher || v > other.CPUSVN[i]
	}
	if lower && higher {
		return 0, ErrNonComparable
	}
	if lower {
		return -1, nil
	}
	if higher {
		return 1, nil
	}
	return 0, nil
}

// TCBM returns the PCCS certificate TCB identifier with little-endian PCESVN.
func (t TCB) TCBM() string {
	b := make([]byte, 18)
	copy(b, t.CPUSVN[:])
	binary.LittleEndian.PutUint16(b[16:], t.PCESVN)
	return strings.ToUpper(hex.EncodeToString(b))
}

// TCBInfo contains the SGX selection metadata from a signed TCB info payload.
// Levels preserve source order for incomparable TCBs.
type TCBInfo struct {
	FMSPC   string
	PCEID   string
	TCBType int
	Levels  []TCB
}

// ParseTCBInfo accepts a TCB info object or an envelope containing tcbInfo.
// Intel v2 legacy component fields and v3 sgxtcbcomponents are supported.
// This parses selection metadata only and does not verify its signature.
func ParseTCBInfo(document []byte) (TCBInfo, error) {
	var out TCBInfo
	if err := validateJSON(document); err != nil {
		return out, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil {
		return out, err
	}
	if payload, ok := object["tcbInfo"]; ok {
		if err := json.Unmarshal(payload, &object); err != nil {
			return out, err
		}
	}
	var wire struct {
		FMSPC  string `json:"fmspc"`
		PCEID  string `json:"pceId"`
		Type   *int   `json:"tcbType"`
		Levels []struct {
			TCB json.RawMessage `json:"tcb"`
		} `json:"tcbLevels"`
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		return out, fmt.Errorf("invalid TCB info: %w", err)
	}
	if wire.Type == nil || *wire.Type != 0 {
		return out, errors.New("TCB info tcbType must be 0")
	}
	if _, err := decodeHex(wire.FMSPC, 6, "FMSPC"); err != nil {
		return out, err
	}
	if _, err := decodeHex(wire.PCEID, 2, "PCEID"); err != nil {
		return out, err
	}
	if len(wire.Levels) == 0 {
		return out, errors.New("TCB info has no TCB levels")
	}
	out.FMSPC, out.PCEID, out.TCBType = strings.ToUpper(wire.FMSPC), strings.ToUpper(wire.PCEID), *wire.Type
	for i, level := range wire.Levels {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(level.TCB, &fields); err != nil {
			return out, fmt.Errorf("TCB level %d: %w", i, err)
		}
		var t TCB
		var pce *uint16
		if err := json.Unmarshal(fields["pcesvn"], &pce); err != nil || pce == nil {
			return out, fmt.Errorf("TCB level %d: invalid pcesvn", i)
		}
		t.PCESVN = *pce
		if components, ok := fields["sgxtcbcomponents"]; ok {
			var values []struct {
				SVN *uint8 `json:"svn"`
			}
			if err := json.Unmarshal(components, &values); err != nil || len(values) != 16 {
				return out, fmt.Errorf("TCB level %d: expected 16 SGX components", i)
			}
			for j, value := range values {
				if value.SVN == nil {
					return out, fmt.Errorf("TCB level %d: component %d missing svn", i, j)
				}
				t.CPUSVN[j] = *value.SVN
			}
		} else {
			for j := range t.CPUSVN {
				var component *uint8
				key := fmt.Sprintf("sgxtcbcomp%02dsvn", j+1)
				if err := json.Unmarshal(fields[key], &component); err != nil || component == nil {
					return out, fmt.Errorf("TCB level %d: missing or invalid %s", i, key)
				}
				t.CPUSVN[j] = *component
			}
		}
		out.Levels = append(out.Levels, t)
	}
	return out, nil
}

func decodeHex(value string, size int, field string) ([]byte, error) {
	if len(value) != size*2 {
		return nil, fmt.Errorf("%s must contain %d hexadecimal characters", field, size*2)
	}
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	return b, nil
}
