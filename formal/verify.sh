#!/usr/bin/env bash
# Runs every ProVerif model. Models in formal/ must prove all their queries;
# models in formal/sanity/ must find an attack (so we know the main models are
# not vacuously true). Uses a local `proverif` if present, otherwise Docker.
set -euo pipefail
cd "$(dirname "$0")"

run() {
  if command -v proverif >/dev/null; then
    proverif "$1"
  else
    docker run --rm -v "$PWD:/m" -w /m "${PROVERIF_IMAGE:-passback-proverif:local}" \
      bash -lc "eval \$(opam env) && proverif $1"
  fi
}

if ! command -v proverif >/dev/null && ! docker image inspect "${PROVERIF_IMAGE:-passback-proverif:local}" >/dev/null 2>&1; then
  docker build -q -t "${PROVERIF_IMAGE:-passback-proverif:local}" - <<'DOCKER'
FROM ocaml/opam:debian-ocaml-5.2
RUN opam update -q && opam install -y proverif.2.05
DOCKER
fi

fail=0
for m in *.pv; do
  out=$(run "$m")
  results=$(grep '^RESULT' <<<"$out" || true)
  echo "== $m"; echo "$results"
  if [[ -z "$results" ]] || grep -qv 'is true\.$' <<<"$results"; then
    echo "FAIL: $m has a query that is not proved"; fail=1
  fi
done
for m in sanity/*.pv; do
  out=$(run "$m")
  results=$(grep '^RESULT' <<<"$out" || true)
  echo "== $m (expects an attack)"; echo "$results"
  if ! grep -q 'is false\.$' <<<"$results"; then
    echo "FAIL: sanity model $m found no attack"; fail=1
  fi
done
exit $fail
