// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package store provides an exclusively locked, transactional JSON store.
// It uses a new on-disk format and cannot open PCCS SQLite databases.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

var (
	ErrClosed            = errors.New("store is closed")
	ErrLocked            = errors.New("store directory is already in use")
	ErrCorrupt           = errors.New("invalid store state")
	ErrReadOnly          = errors.New("transaction is read-only")
	ErrTransactionClosed = errors.New("transaction has ended")
	ErrCapacity          = errors.New("cache exceeds configured storage limit")
	// ErrCommitUncertain means rename succeeded but its directory could not be
	// synced. Reopen the store to inspect the committed state before using it.
	ErrCommitUncertain = errors.New("store commit durability is uncertain; reopen the store")
)

const DefaultMaxBytes int64 = 128 << 20

type state struct {
	Version int                                   `json:"version"`
	Buckets map[string]map[string]json.RawMessage `json:"buckets"`
}

// Store serializes updates and permits concurrent views. Callbacks must not
// recursively call Store methods. Close waits for active callbacks to finish.
type Store struct {
	mu       sync.RWMutex
	checkMu  sync.Mutex
	dir      string
	lock     *os.File
	data     state
	closed   bool
	failure  error
	maxBytes int64
}

// Tx is usable only during its View or Update callback. Values are encoded on
// Put and decoded on Get, so callers never receive references to stored memory.
type Tx struct {
	mu       sync.Mutex
	data     state
	writable bool
	active   bool
	dirty    bool
}

// Open creates or opens a dedicated data directory and locks it until Close.
// The directory is set to mode 0700 and state/lock files to 0600. Corrupt or
// unsupported state is returned as an error and is never reset automatically.
// Process locking is currently supported on Linux.
func Open(dir string) (*Store, error) {
	return OpenWithLimit(dir, DefaultMaxBytes)
}

// OpenWithLimit bounds the encoded snapshot on disk, including after restart.
// Exceeding the limit rejects a transaction without evicting existing data.
func OpenWithLimit(dir string, maxBytes int64) (*Store, error) {
	if maxBytes < 1024 || maxBytes > 1<<30 {
		return nil, errors.New("cache size limit must be between 1024 and 1073741824 bytes")
	}
	if dir == "" {
		return nil, errors.New("store directory is empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve store directory: %w", err)
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect store directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("store path must be a directory, not a symlink: %s", abs)
	}
	if err = os.Chmod(abs, 0700); err != nil {
		return nil, fmt.Errorf("secure store directory: %w", err)
	}
	lock, newLock, err := acquireLock(filepath.Join(abs, ".lock"))
	if err != nil {
		return nil, err
	}
	s := &Store{dir: abs, lock: lock, maxBytes: maxBytes}
	data, err := readState(filepath.Join(abs, "state.json"), maxBytes)
	if errors.Is(err, os.ErrNotExist) {
		if !newLock {
			// Keep .lock after Close so missing state cannot silently erase data.
			err = fmt.Errorf("%w: state.json is missing from an existing store", ErrCorrupt)
		} else {
			data = state{Version: 1, Buckets: make(map[string]map[string]json.RawMessage)}
			err = s.persist(data)
		}
	}
	if err != nil {
		_ = releaseLock(lock)
		return nil, err
	}
	if err = os.Chmod(filepath.Join(abs, "state.json"), 0600); err != nil {
		_ = releaseLock(lock)
		return nil, fmt.Errorf("secure store state: %w", err)
	}
	s.data = data
	return s, nil
}

// Close releases the process lock. Repeated calls are harmless.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return releaseLock(s.lock)
}

// View invokes fn with a consistent read-only snapshot.
func (s *Store) View(fn func(*Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("nil transaction callback")
	}
	tx := &Tx{data: s.data, active: true}
	defer tx.end()
	return fn(tx)
}

// Update commits all callback writes together if fn returns nil. A callback
// error, panic or pre-rename storage failure leaves the previous state intact.
func (s *Store) Update(fn func(*Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("nil transaction callback")
	}
	tx := &Tx{data: clone(s.data), writable: true, active: true}
	defer tx.end()
	if err := fn(tx); err != nil {
		return err
	}
	tx.end()
	if !tx.dirty {
		return nil
	}
	if err := s.persist(tx.data); err != nil {
		if errors.Is(err, ErrCommitUncertain) {
			s.failure = err
		}
		return err
	}
	s.data = tx.data
	return nil
}

// Check validates an actual read of state.json for readiness checks.
func (s *Store) Check() error {
	// Concurrent probes must not each allocate a complete decoded snapshot.
	s.checkMu.Lock()
	defer s.checkMu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return err
	}
	_, err := readState(filepath.Join(s.dir, "state.json"), s.maxBytes)
	return err
}

func (s *Store) available() error {
	if s.closed {
		return ErrClosed
	}
	return s.failure
}

func (tx *Tx) end() {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.active = false
}

// Get decodes a value into dst; missing keys return false without changing dst.
func (tx *Tx) Get(bucket, key string, dst any) (bool, error) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if !tx.active {
		return false, ErrTransactionClosed
	}
	value, ok := tx.data.Buckets[bucket][key]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(value, dst); err != nil {
		return true, fmt.Errorf("decode stored value: %w", err)
	}
	return true, nil
}

// Put creates or replaces a JSON value in the named bucket.
func (tx *Tx) Put(bucket, key string, value any) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if err := tx.canWrite(); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode stored value: %w", err)
	}
	if tx.data.Buckets[bucket] == nil {
		tx.data.Buckets[bucket] = make(map[string]json.RawMessage)
	}
	tx.data.Buckets[bucket][key] = encoded
	tx.dirty = true
	return nil
}

// Delete removes a key; deleting a missing key is harmless.
func (tx *Tx) Delete(bucket, key string) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if err := tx.canWrite(); err != nil {
		return err
	}
	values := tx.data.Buckets[bucket]
	if _, ok := values[key]; ok {
		delete(values, key)
		if len(values) == 0 {
			delete(tx.data.Buckets, bucket)
		}
		tx.dirty = true
	}
	return nil
}

// Keys returns keys in lexical order. An ended transaction returns no keys.
func (tx *Tx) Keys(bucket string) []string {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if !tx.active {
		return nil
	}
	keys := make([]string, 0, len(tx.data.Buckets[bucket]))
	for key := range tx.data.Buckets[bucket] {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (tx *Tx) canWrite() error {
	if !tx.active {
		return ErrTransactionClosed
	}
	if !tx.writable {
		return ErrReadOnly
	}
	return nil
}

func clone(src state) state {
	dst := state{Version: src.Version, Buckets: make(map[string]map[string]json.RawMessage, len(src.Buckets))}
	for bucket, values := range src.Buckets {
		dst.Buckets[bucket] = make(map[string]json.RawMessage, len(values))
		for key, value := range values {
			// Encoded values are immutable and are never exposed to callers.
			dst.Buckets[bucket][key] = value
		}
	}
	return dst
}

func readState(path string, maxBytes int64) (state, error) {
	var data state
	info, err := os.Lstat(path)
	if err != nil {
		return data, fmt.Errorf("read store state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return data, fmt.Errorf("%w: state must be a regular file", ErrCorrupt)
	}
	if info.Size() > maxBytes {
		return data, ErrCapacity
	}
	f, err := os.Open(path)
	if err != nil {
		return data, fmt.Errorf("read store state: %w", err)
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, maxBytes+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&data); err != nil {
		return data, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return data, fmt.Errorf("%w: trailing state data", ErrCorrupt)
	}
	if data.Version != 1 || data.Buckets == nil {
		return data, fmt.Errorf("%w: unsupported version or missing buckets", ErrCorrupt)
	}
	for _, bucket := range data.Buckets {
		if bucket == nil {
			return data, fmt.Errorf("%w: null bucket", ErrCorrupt)
		}
	}
	return data, nil
}

func (s *Store) persist(data state) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode store state: %w", err)
	}
	if int64(len(encoded))+1 > s.maxBytes {
		return ErrCapacity
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("open store directory: %w", err)
	}
	defer dir.Close()
	// Verify directory syncing is supported before replacing the current state.
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("sync store directory: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".state-*")
	if err != nil {
		return fmt.Errorf("create store temporary file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err = tmp.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write store state: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync store state: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close store state: %w", err)
	}
	if err = os.Rename(tmp.Name(), filepath.Join(s.dir, "state.json")); err != nil {
		return fmt.Errorf("replace store state: %w", err)
	}
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	return nil
}
