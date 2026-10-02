Copyright (C) 2025 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause

pck_certificates.json contains the eleven PCK certificate fixtures from
service/pckCertSelection/pckCertSelection.test.js in
https://github.com/intel/confidential-computing.tee.dcap.pccs
at revision 6308e118d962e9ce1b18b9d799164bb056a60a2d. They provide direct parity
coverage for the JavaScript certificate selection implementation. The fixtures
are used for metadata parsing and selection, not as trust anchors or for
certificate signature validation. Cryptographic verification tests generate
their own isolated certificate hierarchy and keys at test runtime.

See ../../../LICENSE for the full BSD-3-Clause license terms and
../../../NOTICE for this independent port's upstream attribution.
