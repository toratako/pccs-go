// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, dir
}

func readInt(t *testing.T, s *Store, bucket, key string) (int, bool) {
	t.Helper()
	var value int
	var found bool
	err := s.View(func(tx *Tx) error {
		var err error
		found, err = tx.Get(bucket, key, &value)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return value, found
}

func TestTransactionsAndRestart(t *testing.T) {
	s, dir := openTestStore(t)
	err := s.Update(func(tx *Tx) error {
		if err := tx.Put("cache", "z", 9); err != nil {
			return err
		}
		return tx.Put("cache", "a", 1)
	})
	if err != nil {
		t.Fatal(err)
	}
	abort := errors.New("abort transaction")
	err = s.Update(func(tx *Tx) error {
		if err := tx.Delete("cache", "a"); err != nil {
			return err
		}
		if err := tx.Put("cache", "z", 20); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatalf("rollback error = %v", err)
	}
	if value, found := readInt(t, s, "cache", "a"); !found || value != 1 {
		t.Fatalf("rollback lost value: %d, %v", value, found)
	}
	if value, found := readInt(t, s, "cache", "z"); !found || value != 9 {
		t.Fatalf("rollback changed value: %d, %v", value, found)
	}
	if err = s.View(func(tx *Tx) error {
		if got := tx.Keys("cache"); !reflect.DeepEqual(got, []string{"a", "z"}) {
			t.Errorf("keys = %v", got)
		}
		if err := tx.Put("cache", "x", 2); !errors.Is(err, ErrReadOnly) {
			t.Errorf("view Put = %v", err)
		}
		if err := tx.Delete("cache", "a"); !errors.Is(err, ErrReadOnly) {
			t.Errorf("view Delete = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if value, found := readInt(t, reopened, "cache", "z"); !found || value != 9 {
		t.Fatalf("reopened value: %d, %v", value, found)
	}
	if err = reopened.Check(); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Update(func(tx *Tx) error { return tx.Delete("cache", "z") }); err != nil {
		t.Fatal(err)
	}
	if _, found := readInt(t, reopened, "cache", "z"); found {
		t.Fatal("deleted key is present")
	}
	for path, want := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, "state.json"): 0600, filepath.Join(dir, ".lock"): 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s permission = %o, want %o", path, got, want)
		}
	}
}

func TestConcurrentUpdates(t *testing.T) {
	s, _ := openTestStore(t)
	const workers, increments = 12, 15
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range increments {
				err := s.Update(func(tx *Tx) error {
					var count int
					if _, err := tx.Get("counts", "total", &count); err != nil {
						return err
					}
					return tx.Put("counts", "total", count+1)
				})
				if err != nil {
					t.Error(err)
					return
				}
				if err := s.View(func(tx *Tx) error {
					var count int
					_, err := tx.Get("counts", "total", &count)
					return err
				}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if value, _ := readInt(t, s, "counts", "total"); value != workers*increments {
		t.Fatalf("lost update: total = %d", value)
	}
}

func TestFailedPersistenceKeepsMemory(t *testing.T) {
	s, dir := openTestStore(t)
	if err := s.Update(func(tx *Tx) error { return tx.Put("cache", "key", 1) }); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the destination forces an actual atomic-rename failure.
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	err = s.Update(func(tx *Tx) error { return tx.Put("cache", "key", 2) })
	if err == nil {
		t.Fatal("update succeeded despite failed rename")
	}
	if value, found := readInt(t, s, "cache", "key"); !found || value != 1 {
		t.Fatalf("failed persistence changed memory: %d, %v", value, found)
	}
	if err = s.Check(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("health check accepted directory state: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".state-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files remain: %v, %v", matches, err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Update(func(tx *Tx) error { return tx.Put("cache", "key", 3) }); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptionNeverResets(t *testing.T) {
	for _, content := range []string{"", "{", `{"version":2,"buckets":{}}`, `{"version":1,"buckets":null}`, `{"version":1,"buckets":{"cache":null}}`, `{"version":1,"buckets":{},"unknown":true}`, `{"version":1,"buckets":{}} {}`} {
		t.Run(content, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if s, err := Open(dir); !errors.Is(err, ErrCorrupt) {
				if s != nil {
					s.Close()
				}
				t.Fatalf("open corrupt state = %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != content {
				t.Fatalf("corrupt state overwritten: %q, %v", got, err)
			}
		})
	}
	// Missing data from a known store must also require explicit intervention.
	s, dir := openTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir); !errors.Is(err, ErrCorrupt) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("missing existing state = %v", err)
	}
}

func TestProcessLock(t *testing.T) {
	if dir := os.Getenv("PCCS_STORE_TEST_LOCK_DIR"); dir != "" {
		s, err := Open(dir)
		if s != nil {
			s.Close()
		}
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("child open = %v", err)
		}
		return
	}
	s, dir := openTestStore(t)
	if other, err := Open(dir); !errors.Is(err, ErrLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("second open = %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessLock$")
	cmd.Env = append(os.Environ(), "PCCS_STORE_TEST_LOCK_DIR="+dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("process lock check: %v\n%s", err, output)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

func TestTransactionLifetimeAndPanic(t *testing.T) {
	s, _ := openTestStore(t)
	var escaped *Tx
	if err := s.Update(func(tx *Tx) error {
		escaped = tx
		return tx.Put("cache", "key", 1)
	}); err != nil {
		t.Fatal(err)
	}
	if err := escaped.Put("cache", "key", 2); !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("escaped Put = %v", err)
	}
	if _, err := escaped.Get("cache", "key", new(int)); !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("escaped Get = %v", err)
	}
	func() {
		defer func() {
			if got := recover(); got != "abort" {
				t.Errorf("panic = %v", got)
			}
		}()
		_ = s.Update(func(tx *Tx) error {
			if err := tx.Put("cache", "key", 3); err != nil {
				t.Fatal(err)
			}
			panic("abort")
		})
	}()
	if value, _ := readInt(t, s, "cache", "key"); value != 1 {
		t.Fatalf("panic committed value %d", value)
	}
	if err := s.Update(func(tx *Tx) error { return tx.Put("cache", "bad", func() {}) }); err == nil {
		t.Fatal("accepted unencodable value")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	checks := []error{s.Check(), s.View(func(*Tx) error { return nil }), s.Update(func(*Tx) error { return nil })}
	for i, err := range checks {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("closed operation %d = %v", i, err)
		}
	}
}
