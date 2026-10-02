// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package collateral parses Intel SGX certificates, selects PCK certificates,
// and verifies collateral with an explicitly supplied certificate trust store.
// Selection does not authenticate its inputs; callers importing untrusted
// collateral must verify certificates and signed documents before persisting it.
package collateral
