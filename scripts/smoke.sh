#!/usr/bin/env bash
# Smoke-tests one release binary on a machine that can run it natively.
#   scripts/smoke.sh <path-to-binary> <rust-target> <expected-version>
# Fails (non-zero) if the binary doesn't start, its self-tests fail, it reports the
# wrong version/target/features, network code is present, or required hardening is
# missing. All comparisons run inside jq so Windows CRLF output can't break them.
set -euo pipefail
bin=$1 target=$2 version=$3
chmod +x "$bin" 2>/dev/null || true

check() { # check <json> <jq filter> <message> [--arg name value]...
  local json=$1 filter=$2 msg=$3; shift 3
  jq -e "$@" "$filter" <<<"$json" >/dev/null || { echo "FAIL: $msg"; echo "$json"; exit 1; }
}

"$bin" selftest >/dev/null

v=$("$bin" version --json)
check "$v" '.version == $v' "version is not $version" --arg v "$version"
check "$v" '.target == $t' "target is not $target" --arg t "$target"
check "$v" '.features == ["cli"]' "default features changed"

s=$("$bin" security --json)
check "$s" '.selftest == "passed"' "self-test not passed"
check "$s" '.network | startswith("none")' "network code present"

case "$target" in
  *-linux-*)   required=("core dumps disabled" "non-dumpable") ;;
  *-apple-*)   required=("core dumps disabled" "PT_DENY_ATTACH") ;;
  *-windows-*) required=("SetErrorMode")
               check "$s" '.hardening_missing | any(contains("debugger"))' "Windows debugger-blocking gap not reported" ;;
  *) echo "FAIL: unknown target $target"; exit 1 ;;
esac
for r in "${required[@]}"; do
  check "$s" '.hardening_applied | any(contains($r))' "missing hardening: $r" --arg r "$r"
done
echo "smoke ok: $target $version"
