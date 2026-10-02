// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/toratako/pccs-go/internal/service"
)

func (h *handler) readObject(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, &service.StatusError{StatusCode: http.StatusUnsupportedMediaType}
	}
	if r.ContentLength > h.maxBodyBytes {
		return nil, &http.MaxBytesError{Limit: h.maxBodyBytes}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	if err != nil {
		return nil, err
	}
	if !strictObject(body) {
		return nil, invalidRequest()
	}
	return body, nil
}

// strictObject rejects duplicate keys, excess nesting, and multiple JSON values.
// json.Unmarshal alone would silently accept repeated fields.
func strictObject(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	if err := readJSONContainer(decoder, '{', 1); err != nil {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func readJSONContainer(decoder *json.Decoder, kind json.Delim, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit exceeded")
	}
	fields := make(map[string]struct{})
	for decoder.More() {
		if kind == '{' {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok {
				return errors.New("invalid JSON key")
			}
			if _, repeated := fields[name]; repeated {
				return errors.New("duplicate JSON key")
			}
			fields[name] = struct{}{}
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if opening, ok := token.(json.Delim); ok {
			if opening != '{' && opening != '[' {
				return errors.New("invalid JSON delimiter")
			}
			if err := readJSONContainer(decoder, opening, depth+1); err != nil {
				return err
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if kind == '{' && closing != json.Delim('}') || kind == '[' && closing != json.Delim(']') {
		return errors.New("invalid JSON close")
	}
	return nil
}

func parsePlatform(body []byte) (service.Platform, error) {
	var platform service.Platform
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return platform, err
	}
	for name, value := range fields {
		switch name {
		case "qe_id", "pce_id", "cpu_svn", "pce_svn", "enc_ppid":
			if bytes.Equal(value, []byte("null")) {
				return platform, invalidRequest()
			}
		case "platform_manifest":
		default:
			return platform, invalidRequest()
		}
	}
	if err := json.Unmarshal(body, &platform); err != nil {
		return platform, err
	}
	if len(platform.QEID) < 1 || len(platform.QEID) > 260 {
		return platform, invalidRequest()
	}
	platform.QEID = strings.ToUpper(platform.QEID)
	var valid bool
	platform.PCEID, valid = normalizedHex(platform.PCEID, 4)
	if !valid {
		return platform, invalidRequest()
	}
	for _, item := range []struct {
		name   string
		value  *string
		length int
	}{
		{"cpu_svn", &platform.CPUSVN, 32}, {"pce_svn", &platform.PCESVN, 4}, {"enc_ppid", &platform.EncPPID, 768},
	} {
		if _, exists := fields[item.name]; exists {
			*item.value, valid = normalizedHex(*item.value, item.length)
			if !valid {
				return platform, invalidRequest()
			}
		}
	}
	return platform, nil
}

func validPolicy(body []byte) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || len(fields) != 3 {
		return false
	}
	for _, name := range []string{"is_default", "fmspc", "policy"} {
		if _, exists := fields[name]; !exists {
			return false
		}
	}
	var policy struct {
		Default *bool  `json:"is_default"`
		FMSPC   string `json:"fmspc"`
		Policy  string `json:"policy"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil || policy.Default == nil || policy.Policy == "" {
		return false
	}
	_, valid := normalizedHex(policy.FMSPC, 12)
	return valid
}
