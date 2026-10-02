// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func acquireLock(path string) (*os.File, bool, error) {
	flags := syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	fd, err := syscall.Open(path, flags|syscall.O_CREAT|syscall.O_EXCL, 0600)
	newLock := err == nil
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Open(path, flags, 0600)
	}
	if err != nil {
		return nil, false, fmt.Errorf("open store lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, false, fmt.Errorf("inspect store lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, false, errors.New("store lock must be a regular file")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, false, ErrLocked
		}
		return nil, false, fmt.Errorf("lock store: %w", err)
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, false, fmt.Errorf("secure store lock: %w", err)
	}
	return f, newLock, nil
}

func releaseLock(f *os.File) error {
	unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	closeErr := f.Close()
	return errors.Join(unlockErr, closeErr)
}
