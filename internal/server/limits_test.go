// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/toratako/pccs-go/internal/service"
)

func TestTokenInputBound(t *testing.T) {
	for _, size := range []int{4096, 4097} {
		token := strings.Repeat("a", size)
		backend := &fakeBackend{}
		h, err := New(Config{AdminTokenHash: tokenHash(token)}, backend, nil)
		if err != nil {
			t.Fatal(err)
		}
		response := request(h, "GET", sgxPrefix+"platforms?source=[]", "", "Admin-Token", token)
		want := http.StatusOK
		if size > 4096 {
			want = http.StatusUnauthorized
		}
		if response.Code != want || size > 4096 && backend.calls != 0 {
			t.Fatalf("token input limit: got %d want %d", response.Code, want)
		}
	}
}

type waitingBackend struct {
	*fakeBackend
	entered chan struct{}
	release chan struct{}
}

func (b *waitingBackend) Get(ctx context.Context, _, _ string, _ url.Values) (service.Response, error) {
	if b.entered != nil {
		b.entered <- struct{}{}
	}
	select {
	case <-b.release:
		return service.Response{Body: []byte("ok")}, nil
	case <-ctx.Done():
		return service.Response{}, ctx.Err()
	}
}

func TestBoundedWorkPreservesLiveness(t *testing.T) {
	backend := &waitingBackend{fakeBackend: &fakeBackend{}, entered: make(chan struct{}, 1), release: make(chan struct{})}
	h, err := New(Config{MaxConcurrentRequests: 1}, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() { done <- request(h, "GET", sgxPrefix+"qe/identity", "", "", "").Code }()
	select {
	case <-backend.entered:
	case <-time.After(time.Second):
		close(backend.release)
		t.Fatal("backend did not start")
	}
	response := request(h, "GET", sgxPrefix+"qe/identity", "", "", "")
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") == "" {
		t.Error("excess work was not refused")
	}
	if response := request(h, "GET", "/healthz/live", "", "", ""); response.Code != http.StatusOK {
		t.Error("liveness unavailable during saturation")
	}
	close(backend.release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("admitted request failed: %d", code)
	}
	if response := request(h, "GET", sgxPrefix+"qe/identity", "", "", ""); response.Code != http.StatusOK {
		t.Fatal("capacity was not released")
	}
}

func TestRequestDeadlineCancelsBackend(t *testing.T) {
	backend := &waitingBackend{fakeBackend: &fakeBackend{}, release: make(chan struct{})}
	h, err := New(Config{RequestTimeout: 10 * time.Millisecond}, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := request(h, "GET", sgxPrefix+"qe/identity", "", "", "")
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("backend deadline: status=%d", response.Code)
	}
}
