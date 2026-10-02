// Copyright (C) 2026 toratako and contributors
// Portions derived from Intel PCCS:
// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"github.com/toratako/pccs-go/internal/pcs"
)

func normalizedHex(value string, length int) (string, bool) {
	if len(value) != length {
		return "", false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", false
	}
	return strings.ToUpper(value), true
}

func normalizeHexQuery(query url.Values, name string, length int, optional bool) bool {
	values, exists := query[name]
	if !exists {
		return optional
	}
	value, valid := normalizedHex(values[0], length)
	if valid {
		query.Set(name, value)
	}
	return valid
}

func normalizeUpdate(query url.Values, all bool) bool {
	update := "standard"
	if values, exists := query["update"]; exists {
		update = strings.ToLower(values[0])
	}
	if update != "standard" && update != "early" && !(all && update == "all") {
		return false
	}
	query.Set("update", update)
	return true
}

func validateQuery(endpoint, method string, query url.Values) bool {
	switch endpoint {
	case "pckcert":
		qeid := query.Get("qeid")
		if len(qeid) < 1 || len(qeid) > 260 {
			return false
		}
		query.Set("qeid", strings.ToUpper(qeid))
		return normalizeHexQuery(query, "cpusvn", 32, false) && normalizeHexQuery(query, "pcesvn", 4, false) && normalizeHexQuery(query, "pceid", 4, false) && normalizeHexQuery(query, "encrypted_ppid", 768, true)
	case "pckcrl":
		ca := strings.ToLower(query.Get("ca"))
		if ca != "processor" && ca != "platform" {
			return false
		}
		query.Set("ca", ca)
		// The original API treats any value other than DER as its legacy hex encoding.
		if encoding, exists := query["encoding"]; exists {
			query.Set("encoding", strings.ToLower(encoding[0]))
		}
		return true
	case "tcb":
		return normalizeHexQuery(query, "fmspc", 12, false) && normalizeUpdate(query, false)
	case "qe/identity", "qve/identity":
		return normalizeUpdate(query, false)
	case "crl":
		uri := query.Get("uri")
		return len(uri) > 0 && len(uri) <= 2048 && pcs.IsAllowedCRLURL(uri)
	case "platforms":
		if method == http.MethodPost {
			return normalizeUpdate(query, true)
		}
		source := query.Get("source")
		if source == "" {
			query.Set("source", "reg")
			return true
		}
		if source == "reg" || source == "reg_na" {
			return true
		}
		if len(source) < 2 || source[0] != '[' || source[len(source)-1] != ']' {
			return false
		}
		content := strings.TrimSpace(source[1 : len(source)-1])
		if content == "" {
			query.Set("source", "[]")
			return true
		}
		fmspcs := strings.Split(content, ",")
		for index, value := range fmspcs {
			var valid bool
			fmspcs[index], valid = normalizedHex(value, 12)
			if !valid {
				return false
			}
		}
		query.Set("source", "["+strings.Join(fmspcs, ",")+"]")
		return true
	case "refresh":
		kind := query.Get("type")
		if kind != "" && kind != "certs" {
			return false
		}
		if kind == "certs" {
			if strings.EqualFold(query.Get("fmspc"), "all") {
				query.Set("fmspc", "all")
				return true
			}
			return normalizeHexQuery(query, "fmspc", 12, false)
		}
		return true
	case "appraisalpolicy":
		return method == http.MethodPut || normalizeHexQuery(query, "fmspc", 12, false)
	}
	return true
}

// Unknown parameters are ignored, as in the original controllers. Never
// forward them to upstream PCS or include them in cache keys.
func filterQuery(endpoint, method string, query url.Values) {
	var names []string
	switch endpoint {
	case "pckcert":
		names = []string{"qeid", "cpusvn", "pcesvn", "pceid", "encrypted_ppid"}
	case "pckcrl":
		names = []string{"ca", "encoding"}
	case "tcb":
		names = []string{"fmspc", "update"}
	case "qe/identity", "qve/identity":
		names = []string{"update"}
	case "crl":
		names = []string{"uri"}
	case "platforms":
		if method == http.MethodPost {
			names = []string{"update"}
		} else {
			names = []string{"source"}
		}
	case "refresh":
		names = []string{"type", "fmspc"}
	case "appraisalpolicy":
		if method == http.MethodGet {
			names = []string{"fmspc"}
		}
	}
	for key := range query {
		allowed := false
		for _, name := range names {
			if key == name {
				allowed = true
				break
			}
		}
		if !allowed {
			delete(query, key)
		}
	}
}
