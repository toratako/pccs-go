// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package store

import (
	"errors"
	"os"
)

func acquireLock(string) (*os.File, bool, error) {
	return nil, false, errors.New("persistent store process locking is supported only on Linux")
}

func releaseLock(f *os.File) error { return f.Close() }
