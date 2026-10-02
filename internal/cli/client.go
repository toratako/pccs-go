// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/toratako/pccs-go/internal/config"
)

var fmspcPattern = regexp.MustCompile(`^[0-9a-fA-F]{12}$`)

func runClient(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	command := args[0]
	rest := args[1:]
	method, endpoint, auth, description := http.MethodGet, "/healthz/ready", "", "Query readiness; a non-success HTTP response returns an error."
	bodyFile, source, fmspc, kind := "", "", "", ""
	switch command {
	case "platforms", "collateral":
		if len(rest) == 1 && (rest[0] == "--help" || rest[0] == "-h") {
			usage := "Usage: pccs platforms list [OPTIONS]\n       pccs platforms register --file PATH|- [OPTIONS]"
			if command == "collateral" {
				usage = "Usage: pccs collateral import --file PATH|- [OPTIONS]"
			}
			_, err := fmt.Fprintln(stdout, usage)
			return err
		}
		if len(rest) == 0 {
			return errors.New("a subcommand is required; use --help")
		}
		command += " " + rest[0]
		rest = rest[1:]
		switch command {
		case "platforms list":
			endpoint, auth = "/sgx/certification/v4/platforms", "admin"
			description = "Fetch JSON platforms. Source reg or reg_na removes the returned entries\nfrom the registration queue. Source [] lists cached platforms without draining.\nA bracketed comma-separated FMSPC list selects cached platforms."
		case "platforms register":
			method, endpoint, auth = http.MethodPost, "/sgx/certification/v4/platforms", "user"
			description = "Register platforms from JSON (--file PATH or --file - for stdin)."
		case "collateral import":
			method, endpoint, auth = http.MethodPut, "/sgx/certification/v4/platformcollateral", "admin"
			description = "Import a PCCS collateral JSON bundle (--file PATH or --file - for stdin)."
		default:
			return errors.New("unknown subcommand; use --help")
		}
	case "refresh":
		method, endpoint, auth = http.MethodPost, "/sgx/certification/v4/refresh", "admin"
		description = "Refresh collateral by default. Use --type certs --fmspc all or a 12-digit\nhexadecimal FMSPC to refresh platform certificates. Requests are not retried."
	}
	fs := flags(command, description+"\n\nConfiguration precedence: options, PCCS_* environment, JSON. HTTP is only\npermitted for an explicit loopback URL. HTTPS certificates are always verified.", stdout)
	configPath := fs.String("config", defaultConfigPath(), "configuration JSON file")
	serverURL := fs.String("url", "", "server origin, e.g. https://localhost:8081")
	ca := fs.String("ca", "", "trusted server CA PEM file (defaults to config directory ca.crt, if present)")
	if command == "platforms list" {
		fs.StringVar(&source, "source", "[]", "platform source: [], reg, reg_na, or [FMSPC,...]")
	}
	if command == "platforms register" || command == "collateral import" {
		fs.StringVar(&bodyFile, "file", "", "JSON input file; - reads stdin (required)")
	}
	if command == "refresh" {
		fs.StringVar(&kind, "type", "", "certs to refresh platform certificates; omitted refreshes collateral")
		fs.StringVar(&fmspc, "fmspc", "", "certificate refresh target: all or 12 hexadecimal digits")
	}
	if done, err := parse(fs, rest); done {
		return err
	}
	query := make(url.Values)
	if command == "platforms list" {
		if !validSource(source) {
			return errors.New("source must be reg, reg_na, [], or [FMSPC,...]")
		}
		query.Set("source", source)
	}
	if command == "refresh" {
		if kind != "" && kind != "certs" {
			return errors.New("refresh type must be certs or omitted")
		}
		if fmspc != "" && fmspc != "all" && !fmspcPattern.MatchString(fmspc) {
			return errors.New("fmspc must be all or 12 hexadecimal digits")
		}
		if fmspc != "" && kind == "" {
			kind = "certs"
		}
		if kind == "certs" {
			if fmspc == "" {
				fmspc = "all"
			}
			query.Set("type", kind)
			query.Set("fmspc", fmspc)
		}
	}
	if (command == "platforms register" || command == "collateral import") && bodyFile == "" {
		return errors.New("--file is required; use --file - for JSON on stdin")
	}
	cfg, err := clientConfig(*configPath, *serverURL, fs)
	if err != nil {
		return err
	}
	u, err := clientURL(*serverURL, cfg.Listen)
	if err != nil {
		return err
	}
	u.Path, u.RawQuery = endpoint, query.Encode()
	var body []byte
	if bodyFile != "" {
		body, err = readJSON(bodyFile, stdin, cfg.MaxBodyBytes)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("could not construct request")
	}
	if bodyFile != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		token, err := loadToken(auth, *configPath)
		if err != nil {
			return err
		}
		req.Header.Set(auth+"-token", token)
	}
	client, err := newHTTPClient(*ca, *configPath)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("request failed; verify server address, CA trust, and connectivity (the request may have reached the server)")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("server returned HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, (16<<20)+1))
	if err != nil {
		return errors.New("could not read server response; the request may have completed")
	}
	if len(data) > 16<<20 {
		return errors.New("server response exceeds 16 MiB; the request may have completed")
	}
	if len(data) == 0 {
		_, err = fmt.Fprintln(stdout, "Request completed.")
		return err
	}
	if _, err = stdout.Write(data); err != nil {
		return err
	}
	if data[len(data)-1] != '\n' {
		_, err = fmt.Fprintln(stdout)
	}
	return err
}

func clientConfig(path, serverURL string, fs *flag.FlagSet) (config.Config, error) {
	cfg, err := config.Load(path)
	if err == nil {
		return cfg, nil
	}
	explicit := os.Getenv("PCCS_CONFIG") != ""
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			explicit = true
		}
	})
	if serverURL != "" && !explicit && errors.Is(err, os.ErrNotExist) {
		return config.Default(), nil
	}
	return config.Config{}, err
}

func clientURL(raw, listen string) (*url.URL, error) {
	if raw == "" {
		host, port, err := net.SplitHostPort(listen)
		if err != nil {
			return nil, errors.New("cannot derive server URL from listen address; supply --url")
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "localhost"
		}
		raw = "https://" + net.JoinHostPort(host, port)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("--url must be an HTTP(S) server origin without credentials, path, query, or fragment")
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return nil, errors.New("HTTP is only allowed for loopback; use HTTPS for remote servers")
	}
	return u, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newHTTPClient(caPath, configPath string) (*http.Client, error) {
	if caPath == "" {
		candidate := filepath.Join(filepath.Dir(configPath), "ca.crt")
		if _, err := os.Stat(candidate); err == nil {
			caPath = candidate
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("could not inspect default CA file")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		data, err := os.ReadFile(caPath)
		if err != nil {
			return nil, errors.New("could not read CA file")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("CA file contains no valid PEM certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func loadToken(kind, configPath string) (string, error) {
	if value := os.Getenv("PCCS_" + strings.ToUpper(kind) + "_TOKEN"); value != "" {
		return cleanToken(value)
	}
	f, err := os.Open(filepath.Join(filepath.Dir(configPath), kind+".token"))
	if err != nil {
		return "", fmt.Errorf("%s token unavailable; set PCCS_%s_TOKEN or use the token file beside configuration", kind, strings.ToUpper(kind))
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", errors.New("could not read token file")
	}
	return cleanToken(string(data))
}

func readJSON(path string, stdin io.Reader, limit int64) ([]byte, error) {
	reader := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, errors.New("could not open JSON input file")
		}
		defer f.Close()
		reader = f
	}
	if limit <= 0 {
		limit = 16 << 20
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, errors.New("could not read JSON input")
	}
	if int64(len(data)) > limit {
		return nil, errors.New("JSON input exceeds the configured body limit")
	}
	if !json.Valid(data) {
		return nil, errors.New("input must contain one valid JSON value")
	}
	return data, nil
}

func validSource(source string) bool {
	if source == "reg" || source == "reg_na" || source == "[]" {
		return true
	}
	if !strings.HasPrefix(source, "[") || !strings.HasSuffix(source, "]") {
		return false
	}
	items := strings.TrimSpace(source[1 : len(source)-1])
	if items == "" {
		return true
	}
	for _, item := range strings.Split(items, ",") {
		if !fmspcPattern.MatchString(strings.TrimSpace(item)) {
			return false
		}
	}
	return true
}
