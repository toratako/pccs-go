# Contributing

Work from this standalone repository's root on Linux with Go 1.23+.
See [README](README.md) for project scope, the
[bug report form](.github/ISSUE_TEMPLATE/bug_report.yml) for ordinary issues,
and [SECURITY](SECURITY.md) for vulnerabilities.

```sh
make check  # race tests, vet, formatting
make smoke  # build and exercise an offline TLS instance
```

Tests need local TCP listeners, not PCS credentials or SGX/TDX hardware.
Document and test behavior changes. Keep external Go dependencies absent unless
needed (see [go.mod](go.mod)); no `go.sum` is currently required.
Sign off commits (`git commit -s`) under the
[DCO](https://developercertificate.org/). Contributions use [BSD-3-Clause](LICENSE);
attribute new work to its authors and retain upstream notices, updating
[NOTICE](NOTICE) for added upstream material.

For automation/packaging changes, install [actionlint](https://github.com/rhysd/actionlint),
[ShellCheck](https://www.shellcheck.net/), and
[GoReleaser](https://goreleaser.com/getting-started/install/oss/), then run:

```sh
make lint-ci release-check release-snapshot
```

Use versions pinned in [CI](.github/workflows/ci.yml). Release tooling requires
an `origin` remote. Snapshots replace `dist/`, need no GitHub token, and do not
publish; inspect archive contents and verify `dist/checksums.txt`.

[CI](.github/workflows/ci.yml) defines the test matrix; minimum Go checks source
compatibility, while releases and [vulnerability scans](.github/workflows/security.yml)
use latest stable Go. [Dependabot](.github/dependabot.yml) updates Action pins
and modules; embedded actionlint, govulncheck, and GoReleaser versions require
manual updates and snapshot validation.

## GitHub setup

Publish this directory as the repository root: GitHub does not discover
workflows under a parent repository's `go_port/.github`. Keep the module path
in `go.mod`, internal imports, and [.goreleaser.yaml](.goreleaser.yaml) aligned.

Configure these in GitHub; the files do not enforce them:

- Enable Actions and allow the pinned Actions.
- Require `CI passed` and `Go vulnerability check` on `main`; merge queues are supported.
- Restrict creation, update, and deletion of `v*` tags to release maintainers.
- Enable private vulnerability reporting.

CI is read-only without persisted Git credentials; only release publication
uses `contents: write` with the automatic `GITHUB_TOKEN`. No PAT or PCS secrets
are needed. Runs and artifacts consume the repository's Actions allowance.

## Releases

From a clean, reviewed `main` commit, choose an unused semantic-version tag:

```sh
git tag -a v0.1.0 -m 'PCCS in Go v0.1.0 (unofficial)'
git push origin v0.1.0
```

The [release workflow](.github/workflows/release.yml) requires CI and vulnerability
checks to pass for that commit. [.goreleaser.yaml](.goreleaser.yaml) defines
architectures, archive contents, checksums, and version embedding.
`v0.1.0-rc.1` creates a prerelease;
[release.yml](.github/release.yml) groups generated notes, retaining uncategorized
changes under “Other changes”. CI snapshots are development artifacts.

Do not pre-publish the release: the workflow creates a draft, uploads, then
publishes. On failure, inspect the run and remaining draft before retrying.
Never move a published tag; issue a new version for corrections.
