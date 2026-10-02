#!/usr/bin/env bash
# Exercise a built executable with a disposable, offline TLS instance.
set -euo pipefail

binary=$(realpath -- "${1:-bin/pccs}")
expected_version=${2:-}
test -x "$binary"

# Do not inherit credentials, paths, or configuration from a developer's instance.
for variable in "${!PCCS_@}"; do
	unset "$variable"
done
export PCCS_UPSTREAM_TIMEOUT=2s PCCS_SHUTDOWN_TIMEOUT=5s PCCS_REFRESH_INTERVAL=0s
export NO_PROXY=localhost,127.0.0.1,::1

smoke_dir=$(mktemp -d)
server_pid=
cleanup() {
	status=$?
	trap - EXIT
	if [[ -n "$server_pid" ]]; then
		kill "$server_pid" 2>/dev/null || true
		wait "$server_pid" 2>/dev/null || true
	fi
	if ((status != 0)) && [[ -f "$smoke_dir/server.log" ]]; then
		cat "$smoke_dir/server.log" >&2
	fi
	rm -rf -- "$smoke_dir"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

actual_version=$("$binary" version)
if [[ -n "$expected_version" ]]; then
	test "$actual_version" = "$expected_version"
fi
"$binary" --help >/dev/null
"$binary" init --dir "$smoke_dir/instance" >/dev/null
config_path="$smoke_dir/instance/config.json"
"$binary" config check --config "$config_path"
"$binary" serve --config "$config_path" --listen 127.0.0.1:0 --mode OFFLINE >"$smoke_dir/server.log" 2>&1 &
server_pid=$!

address=
for ((attempt = 0; attempt < 100; attempt++)); do
	if ! kill -0 "$server_pid" 2>/dev/null; then
		echo 'PCCS exited before becoming ready.' >&2
		exit 1
	fi
	address=$(sed -n 's/.*address=\(127\.0\.0\.1:[0-9]*\).*/\1/p' "$smoke_dir/server.log")
	if [[ -n "$address" ]]; then
		break
	fi
	sleep 0.1
done
if [[ -z "$address" ]]; then
	echo 'PCCS did not report its listener within 10 seconds.' >&2
	exit 1
fi

"$binary" health --config "$config_path" --url "https://$address"
"$binary" platforms list --config "$config_path" --url "https://$address" --source '[]'
kill "$server_pid"
wait "$server_pid"
server_pid=
printf 'Smoke test passed (version %s).\n' "$actual_version"
