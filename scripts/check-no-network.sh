#!/usr/bin/env bash
# Fails if any networking crate is linked into the passback binary.
# The binary must make no network connections unless a feature that needs them
# (daemon, server, browser, agent) is compiled in; this check covers the default
# build and, until those features gain code, every feature combination.
set -euo pipefail
cd "$(dirname "$0")/.."

banned='^(reqwest|hyper|hyper-util|h2|h3|ureq|curl|curl-sys|isahc|attohttpc|socket2|mio|tokio|async-std|smol|rustls|native-tls|openssl|quinn|tungstenite|tokio-tungstenite|surf|trust-dns-resolver|hickory-resolver|sentry|opentelemetry|tracing-opentelemetry|axum|actix-web|warp|rocket|tonic)$'

check() {
    local label=$1; shift
    local found
    found=$(cargo tree -p passback -e normal --prefix none --format '{p}' "$@" | awk '{print $1}' | sort -u | grep -E "$banned" || true)
    if [[ -n "$found" ]]; then
        echo "FAIL ($label): networking crates linked:"; echo "$found"; exit 1
    fi
    echo "ok ($label): no networking crates"
}

check "default features"
check "no default features" --no-default-features
check "all features" --features full
