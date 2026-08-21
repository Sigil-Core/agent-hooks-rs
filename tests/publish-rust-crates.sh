#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
publisher="${repository_root}/scripts/publish-rust-crates.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/agent-hooks-rs-publish.XXXXXX")"

cleanup() {
  if [[ -n "${test_root}" && -d "${test_root}" ]]; then
    rm -rf -- "${test_root}"
  fi
}
trap cleanup EXIT

fake_bin="${test_root}/bin"
mkdir -p "${fake_bin}"

cat > "${fake_bin}/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-}"
shift || true

case "${command_name}" in
  metadata)
    printf 'metadata\n' >> "${FAKE_CARGO_LOG}"
    printf '{"packages":[{"name":"sigil-agent-hooks-core","version":"%s"},{"name":"sigil-agent-hooks-ironclaw","version":"%s"}]}\n' \
      "${FAKE_CORE_VERSION:-0.4.0}" \
      "${FAKE_IRONCLAW_VERSION:-0.4.0}"
    ;;
  info)
    crate_spec="${1:?missing crate spec}"
    crate="${crate_spec%@*}"
    printf 'info %s\n' "${crate_spec}" >> "${FAKE_CARGO_LOG}"

    if [[ -f "${FAKE_CARGO_STATE}/${crate}.available" ]]; then
      exit 0
    fi

    if [[ -f "${FAKE_CARGO_STATE}/${crate}.remaining" ]]; then
      remaining="$(<"${FAKE_CARGO_STATE}/${crate}.remaining")"
      if ((remaining == 0)); then
        : > "${FAKE_CARGO_STATE}/${crate}.available"
        exit 0
      fi
      printf '%s\n' "$((remaining - 1))" > "${FAKE_CARGO_STATE}/${crate}.remaining"
    fi
    exit 1
    ;;
  publish)
    crate=""
    while (($# > 0)); do
      if [[ "$1" == "-p" ]]; then
        crate="${2:?missing package after -p}"
        break
      fi
      shift
    done
    [[ -n "${crate}" ]] || exit 64
    printf 'publish %s\n' "${crate}" >> "${FAKE_CARGO_LOG}"
    printf '%s\n' "${FAKE_PROPAGATION_POLLS:-0}" > "${FAKE_CARGO_STATE}/${crate}.remaining"
    ;;
  *)
    exit 64
    ;;
esac
FAKE_CARGO
chmod 700 "${fake_bin}/cargo"

reset_case() {
  case_name="$1"
  case_root="${test_root}/${case_name}"
  state_dir="${case_root}/state"
  log_file="${case_root}/cargo.log"
  mkdir -p "${state_dir}"
  : > "${log_file}"
}

run_publisher() {
  PATH="${fake_bin}:${PATH}" \
    FAKE_CARGO_LOG="${log_file}" \
    FAKE_CARGO_STATE="${state_dir}" \
    FAKE_PROPAGATION_POLLS="${FAKE_PROPAGATION_POLLS:-0}" \
    FAKE_CORE_VERSION="${FAKE_CORE_VERSION:-0.4.0}" \
    FAKE_IRONCLAW_VERSION="${FAKE_IRONCLAW_VERSION:-0.4.0}" \
    SIGIL_CRATES_IO_MAX_ATTEMPTS="${SIGIL_CRATES_IO_MAX_ATTEMPTS:-4}" \
    SIGIL_CRATES_IO_RETRY_SECONDS=0 \
    bash "${publisher}" 0.4.0
}

reset_case fresh
FAKE_PROPAGATION_POLLS=2 run_publisher
published="$(grep '^publish ' "${log_file}")"
expected=$'publish sigil-agent-hooks-core\npublish sigil-agent-hooks-ironclaw'
[[ "${published}" == "${expected}" ]]
[[ "$(grep -c '^info sigil-agent-hooks-core@0.4.0$' "${log_file}")" -ge 4 ]]

reset_case retry
: > "${state_dir}/sigil-agent-hooks-core.available"
: > "${state_dir}/sigil-agent-hooks-ironclaw.available"
run_publisher
if grep -q '^publish ' "${log_file}"; then
  echo "publish-rust-crates test: retry republished an available crate" >&2
  exit 1
fi

reset_case partial
: > "${state_dir}/sigil-agent-hooks-core.available"
FAKE_PROPAGATION_POLLS=1 run_publisher
published="$(grep '^publish ' "${log_file}")"
[[ "${published}" == "publish sigil-agent-hooks-ironclaw" ]]

reset_case timeout
if FAKE_PROPAGATION_POLLS=10 SIGIL_CRATES_IO_MAX_ATTEMPTS=2 run_publisher >"${case_root}/stdout" 2>"${case_root}/stderr"; then
  echo "publish-rust-crates test: unavailable core unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'sigil-agent-hooks-core@0.4.0 was not available after 2 checks' "${case_root}/stderr"
if grep -q '^publish sigil-agent-hooks-ironclaw$' "${log_file}"; then
  echo "publish-rust-crates test: dependent crate published before core availability" >&2
  exit 1
fi

reset_case mismatch
if FAKE_IRONCLAW_VERSION=0.4.1 run_publisher >"${case_root}/stdout" 2>"${case_root}/stderr"; then
  echo "publish-rust-crates test: mismatched manifest version unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'sigil-agent-hooks-ironclaw manifest version 0.4.1 does not match release 0.4.0' "${case_root}/stderr"
if grep -q '^publish ' "${log_file}"; then
  echo "publish-rust-crates test: version mismatch published a crate" >&2
  exit 1
fi

if bash "${publisher}" invalid-version >"${test_root}/invalid.stdout" 2>"${test_root}/invalid.stderr"; then
  echo "publish-rust-crates test: invalid version unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'invalid crate version' "${test_root}/invalid.stderr"

echo "publish-rust-crates test: all cases passed"
