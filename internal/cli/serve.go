// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/toratako/pccs-go/internal/config"
	"github.com/toratako/pccs-go/internal/pcs"
	"github.com/toratako/pccs-go/internal/server"
	"github.com/toratako/pccs-go/internal/service"
	"github.com/toratako/pccs-go/internal/store"
)

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flags("serve", "Run PCCS with TLS. --http explicitly enables plaintext HTTP only on a\nloopback listener, for a local reverse proxy or development. CLI options\noverride PCCS_* environment variables and JSON configuration.", stdout)
	path := fs.String("config", defaultConfigPath(), "configuration JSON file")
	listen := fs.String("listen", "", "override listener address (host:port)")
	mode := fs.String("mode", "", "override caching mode: LAZY, REQ, OFFLINE")
	dataDir := fs.String("data-dir", "", "override dedicated cache data directory")
	plainHTTP := fs.Bool("http", false, "serve HTTP on loopback instead of HTTPS")
	if done, err := parse(fs, args); done {
		return err
	}
	cfg, err := config.LoadWithOverrides(*path, func(cfg *config.Config) {
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "listen":
				cfg.Listen = *listen
			case "mode":
				cfg.Mode = *mode
			case "data-dir":
				cfg.DataDir = *dataDir
			}
		})
	})
	if err != nil {
		return err
	}
	if *plainHTTP {
		host, _, err := net.SplitHostPort(cfg.Listen)
		if err != nil || !loopbackHost(host) {
			return errors.New("--http requires a loopback listen address")
		}
	}
	var certificate tls.Certificate
	if !*plainHTTP {
		certificate, err = tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return errors.New("could not load TLS certificate and key; run pccs init or check TLS paths")
		}
	}
	timeout, err := time.ParseDuration(cfg.UpstreamTimeout)
	if err != nil {
		return errors.New("invalid upstream timeout")
	}
	interval, err := time.ParseDuration(cfg.RefreshInterval)
	if err != nil {
		return errors.New("invalid refresh interval")
	}
	shutdownTimeout, err := time.ParseDuration(cfg.ShutdownTimeout)
	if err != nil {
		return errors.New("invalid shutdown timeout")
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return errors.New("invalid log level")
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	var roots *x509.CertPool
	if cfg.CollateralRootCA != "" {
		data, err := os.ReadFile(cfg.CollateralRootCA)
		if err != nil {
			return errors.New("could not read collateral root CA file")
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return errors.New("collateral root CA file contains no valid certificates")
		}
	}
	upstream, err := pcs.New(pcs.Config{BaseURL: cfg.PCSURL, APIKey: cfg.APIKey, Proxy: cfg.Proxy, Timeout: timeout})
	if err != nil {
		return err
	}
	db, err := store.OpenWithLimit(cfg.DataDir, cfg.MaxCacheBytes)
	if err != nil {
		return err
	}
	defer db.Close()
	svc, err := service.New(service.Config{Mode: cfg.Mode, Roots: roots}, db, upstream)
	if err != nil {
		return err
	}
	writeTimeout := 5 * time.Minute
	if timeout+15*time.Second > writeTimeout {
		writeTimeout = timeout + 15*time.Second
	}
	handler, err := server.New(server.Config{UserTokenHash: cfg.UserTokenHash, AdminTokenHash: cfg.AdminTokenHash, MaxBodyBytes: cfg.MaxBodyBytes, MaxConcurrentRequests: cfg.MaxConcurrentRequests, RequestTimeout: writeTimeout}, svc, logger)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return errors.New("could not open listener; check the listen address and port availability")
	}
	defer listener.Close()
	if !*plainHTTP {
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	}
	requests, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	tracked := &trackedHandler{next: handler}
	httpServer := &http.Server{
		Handler:           tracked,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      writeTimeout + time.Second,
		MaxHeaderBytes:    16 << 10,
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return requests },
		ErrorLog:          log.New(&serverLog{logger: logger}, "", 0),
	}
	background, cancelBackground := context.WithCancel(ctx)
	defer cancelBackground()
	var refresh sync.WaitGroup
	if interval > 0 && cfg.Mode != "OFFLINE" {
		refresh.Add(1)
		go func() {
			defer refresh.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-background.Done():
					return
				case <-ticker.C:
					if err := svc.Refresh(background, "", ""); err != nil && background.Err() == nil {
						logger.Error("background collateral refresh failed")
					}
				}
			}
		}()
	}
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(listener) }()
	scheme := "https"
	if *plainHTTP {
		scheme = "http"
	}
	logger.Info("PCCS listening", "scheme", scheme, "address", listener.Addr().String(), "mode", cfg.Mode)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-served:
	}
	cancelBackground()
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	shutdownErr := httpServer.Shutdown(shutdown)
	cancelShutdown()
	if shutdownErr != nil {
		cancelRequests()
		_ = httpServer.Close()
	}
	tracked.stopAndWait()
	cancelRequests()
	refresh.Wait()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.New("HTTP server stopped unexpectedly")
	}
	if shutdownErr != nil {
		return errors.New("graceful shutdown timed out; active requests were canceled")
	}
	return nil
}

// Gate new handlers before waiting so Close cannot race a late handler start.
type trackedHandler struct {
	next    http.Handler
	mu      sync.Mutex
	stopped bool
	wg      sync.WaitGroup
}

func (h *trackedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		http.Error(w, "Service unavailable.", http.StatusServiceUnavailable)
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()
	h.next.ServeHTTP(w, r)
}

func (h *trackedHandler) stopAndWait() {
	h.mu.Lock()
	h.stopped = true
	h.mu.Unlock()
	h.wg.Wait()
}

// net/http diagnostics can contain request-controlled details. Keep the event
// observable without copying raw diagnostics or request data into logs.
type serverLog struct{ logger *slog.Logger }

func (w *serverLog) Write(p []byte) (int, error) {
	w.logger.Warn("HTTP connection error")
	return len(p), nil
}
