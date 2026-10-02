// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapacityFailureIsAtomicAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenWithLimit(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Update(func(tx *Tx) error { return tx.Put("cache", "existing", 1) }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = s.Update(func(tx *Tx) error {
		if err := tx.Put("cache", "existing", 2); err != nil {
			return err
		}
		return tx.Put("cache", "new", strings.Repeat("a", 1024))
	})
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity was not enforced: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed update changed disk")
	}
	if value, _ := readInt(t, s, "cache", "existing"); value != 1 {
		t.Fatal("failed update changed memory")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithLimit(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if value, _ := readInt(t, reopened, "cache", "existing"); value != 1 {
		t.Fatal("reopened state changed")
	}
}

func TestReducedCapacityPreservesExistingSnapshot(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenWithLimit(dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(tx *Tx) error { return tx.Put("cache", "data", strings.Repeat("x", 1536)) }); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := OpenWithLimit(dir, 1024); !errors.Is(err, ErrCapacity) {
		if unexpected != nil {
			unexpected.Close()
		}
		t.Fatalf("oversize existing snapshot was accepted: %v", err)
	}
	reopened, err := OpenWithLimit(dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.View(func(tx *Tx) error {
		var data string
		found, err := tx.Get("cache", "data", &data)
		if !found || len(data) != 1536 {
			t.Error("rejected startup changed data")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
