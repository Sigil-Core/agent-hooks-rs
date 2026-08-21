#!/usr/bin/env bash

set -euo pipefail

version="${1:-}"
max_attempts="${SIGIL_CRATES_IO_MAX_ATTEMPTS:-30}"
retry_seconds="${SIGIL_CRATES_IO_RETRY_SECONDS:-10}"

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "publish-rust-crates: invalid crate version: ${version:-<empty>}" >&2
  exit 2
fi

if [[ ! "${max_attempts}" =~ ^[1-9][0-9]*$ ]]; then
  echo "publish-rust-crates: SIGIL_CRATES_IO_MAX_ATTEMPTS must be a positive integer" >&2
  exit 2
fi

if [[ ! "${retry_seconds}" =~ ^[0-9]+$ ]]; then
  echo "publish-rust-crates: SIGIL_CRATES_IO_RETRY_SECONDS must be a non-negative integer" >&2
  exit 2
fi

metadata_json="$(cargo metadata --locked --no-deps --format-version 1)"

package_manifest_version() {
  local crate="$1"
  python3 -c '
import json
import sys

matches = [
    package
    for package in json.load(sys.stdin)["packages"]
    if package["name"] == sys.argv[1]
]
if len(matches) != 1:
    raise SystemExit(f"expected one workspace package named {sys.argv[1]}")
print(matches[0]["version"])
' "${crate}" <<< "${metadata_json}"
}

for crate in sigil-agent-hooks-core sigil-agent-hooks-ironclaw; do
  manifest_version="$(package_manifest_version "${crate}")"
  if [[ "${manifest_version}" != "${version}" ]]; then
    echo "publish-rust-crates: ${crate} manifest version ${manifest_version} does not match release ${version}" >&2
    exit 2
  fi
done

crate_is_available() {
  local crate="$1"
  cargo info "${crate}@${version}" --registry crates-io >/dev/null 2>&1
}

wait_for_crate() {
  local crate="$1"
  local attempt

  for ((attempt = 1; attempt <= max_attempts; attempt += 1)); do
    if crate_is_available "${crate}"; then
      echo "publish-rust-crates: ${crate}@${version} is available from crates.io"
      return 0
    fi

    if ((attempt == max_attempts)); then
      echo "publish-rust-crates: ${crate}@${version} was not available after ${max_attempts} checks" >&2
      return 1
    fi

    echo "publish-rust-crates: waiting for ${crate}@${version} (${attempt}/${max_attempts})"
    sleep "${retry_seconds}"
  done
}

publish_if_missing() {
  local crate="$1"

  if crate_is_available "${crate}"; then
    echo "publish-rust-crates: ${crate}@${version} is already published; skipping"
    return 0
  fi

  cargo publish -p "${crate}" --locked
  wait_for_crate "${crate}"
}

publish_if_missing sigil-agent-hooks-core
publish_if_missing sigil-agent-hooks-ironclaw
