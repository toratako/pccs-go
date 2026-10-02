// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/toratako/pccs-go/internal/config"
	"github.com/toratako/pccs-go/internal/store"
)

func TestHandlerShutdownWaitsAndRejectsLateRequests(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := &trackedHandler{next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})}
	response := httptest.NewRecorder()
	go h.ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	<-entered
	stopped := make(chan struct{})
	go func() { h.stopAndWait(); close(stopped) }()
	// Synchronize with the stop gate without using timing as proof of shutdown.
	deadline := time.Now().Add(time.Second)
	for {
		h.mu.Lock()
		gated := h.stopped
		h.mu.Unlock()
		if gated {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shutdown gate did not close")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-stopped:
		t.Fatal("shutdown returned while a handler was running")
	default:
	}
	late := httptest.NewRecorder()
	h.ServeHTTP(late, httptest.NewRequest("GET", "/", nil))
	if late.Code != http.StatusServiceUnavailable {
		t.Fatalf("late request status: %d", late.Code)
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not wait for handler completion")
	}
	if response.Code != http.StatusOK {
		t.Fatalf("active request status: %d", response.Code)
	}
}

type notificationWriter struct {
	mu        sync.Mutex
	data      bytes.Buffer
	listening chan struct{}
	once      sync.Once
	address   string
}

func (w *notificationWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.data.Write(p)
	if bytes.Contains(p, []byte("PCCS listening")) {
		for _, field := range strings.Fields(string(p)) {
			if strings.HasPrefix(field, "address=") {
				w.address = strings.TrimPrefix(field, "address=")
			}
		}
		w.once.Do(func() { close(w.listening) })
	}
	return n, err
}

func TestServeCancellationReleasesStore(t *testing.T) {
	t.Setenv("PCCS_CONFIG", "")
	t.Setenv("PCCS_ADMIN_TOKEN", "")
	dir := filepath.Join(t.TempDir(), "pccs")
	path, err := config.Initialize(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = "127.0.0.1:0"
	cfg.Mode = "OFFLINE"
	cfg.RefreshInterval = "0s"
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	diagnostics := &notificationWriter{listening: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, []string{"serve", "--config", path}, strings.NewReader(""), io.Discard, diagnostics)
	}()
	select {
	case <-diagnostics.listening:
	case err := <-done:
		t.Fatalf("serve failed before listening: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not start")
	}
	diagnostics.mu.Lock()
	address := diagnostics.address
	diagnostics.mu.Unlock()
	if address == "" {
		t.Fatal("listener address was not reported")
	}
	stdout, _, err := invoke([]string{"health", "--config", path, "--url", "https://" + address}, "")
	if err != nil || !strings.Contains(stdout, `"status":"UP"`) {
		t.Fatalf("generated TLS and readiness: output=%q error=%v", stdout, err)
	}
	stdout, _, err = invoke([]string{"platforms", "list", "--config", path, "--url", "https://" + address}, "")
	if err != nil || stdout != "[]\n" {
		t.Fatalf("generated admin token: output=%q error=%v", stdout, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop")
	}
	db, err := store.Open(cfg.DataDir)
	if err != nil {
		t.Fatalf("store remained locked after shutdown: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPListenerRequiresLoopback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pccs")
	path, err := config.Initialize(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = invoke([]string{"serve", "--config", path, "--http", "--listen", "0.0.0.0:8081"}, "")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("remote HTTP accepted: %v", err)
	}
}
