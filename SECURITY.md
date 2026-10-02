# Security policy

This covers toratako's independent Go port, with no Intel affiliation or support.

## Reporting a vulnerability

Use **Report a vulnerability** in this repository's Security tab. If disabled,
ask the maintainer for a private channel without disclosing details publicly.
Do not post vulnerabilities in public issues or pull requests. Independently
confirmed upstream PCCS/PCS issues follow upstream's security policy.

Include version/commit, Linux distribution/architecture, cache mode, impact,
and affected behavior. Remove tokens, subscription keys, private keys, and
private platform data from attachments.

## Versions and updates

Fixes target `main` and the latest published release, on a best-effort basis:
no guaranteed response/fix timeline or older-version backports. Prereleases
and CI snapshots are development builds. `go.mod` sets source compatibility;
deploy with a supported, patched Go toolchain.

CI scans reachable code and the standard library; passing does not establish
hardware interoperability or replace deployment review. See
[TLS and trust](README.md#tls-and-trust) for authentication, collateral roots,
ingress limits, and cache handling.
