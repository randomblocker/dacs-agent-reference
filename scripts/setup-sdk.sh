#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_DIR="${ROOT_DIR}/sdk"
SDK_REPOSITORY="${DACS_SDK_REPOSITORY:-https://github.com/DACS-Agent-commerce/dacs-sdk.git}"
SDK_REV="${DACS_SDK_REV:-a9b0d11cbf4aba2b9ab49926206af88bdbc21ae7}"

git_with_sdk_auth() {
  if [[ -n "${DACS_SDK_GITHUB_TOKEN:-}" ]]; then
    local encoded
    encoded="$(printf 'x-access-token:%s' "${DACS_SDK_GITHUB_TOKEN}" | base64 | tr -d '\n')"
    git -c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${encoded}" "$@"
  else
    git "$@"
  fi
}

if [[ -n "${DACS_SDK_PATH:-}" ]]; then
  source_dir="$(cd "${DACS_SDK_PATH}" && pwd)"
  if [[ ! -f "${source_dir}/package.json" || ! -d "${source_dir}/.git" ]]; then
    echo "DACS_SDK_PATH must point to a DACS SDK git checkout" >&2
    exit 1
  fi
  source_rev="$(git -C "${source_dir}" rev-parse HEAD)"
  if [[ "${source_rev}" != "${SDK_REV}" && "${DACS_SDK_ALLOW_UNPINNED:-0}" != "1" ]]; then
    echo "DACS_SDK_PATH is at ${source_rev}, expected ${SDK_REV}" >&2
    echo "Check out the pinned revision or set DACS_SDK_ALLOW_UNPINNED=1 explicitly." >&2
    exit 1
  fi
  if [[ -e "${SDK_DIR}" && ! -L "${SDK_DIR}" ]]; then
    echo "Refusing to replace the unexpected path at ${SDK_DIR}" >&2
    exit 1
  fi
  rm -f "${SDK_DIR}"
  ln -s "${source_dir}" "${SDK_DIR}"
elif [[ -d "${SDK_DIR}/.git" ]]; then
  git_with_sdk_auth -C "${SDK_DIR}" fetch --depth 1 origin "${SDK_REV}"
  git -C "${SDK_DIR}" checkout --detach "${SDK_REV}"
elif [[ -f "${SDK_DIR}/package.json" && -d "${SDK_DIR}/dist" ]]; then
  echo "Using the packaged SDK already present at ${SDK_DIR}"
else
  if [[ -e "${SDK_DIR}" ]]; then
    echo "Refusing to replace the unexpected path at ${SDK_DIR}" >&2
    exit 1
  fi
  git_with_sdk_auth clone --no-checkout "${SDK_REPOSITORY}" "${SDK_DIR}"
  git_with_sdk_auth -C "${SDK_DIR}" fetch --depth 1 origin "${SDK_REV}"
  git -C "${SDK_DIR}" checkout --detach "${SDK_REV}"
fi

cd "${ROOT_DIR}"
rm -f node_modules/@kynesyslabs/dacs
npm install --no-audit --no-fund

(
  cd "${SDK_DIR}"
  npm install --no-audit --no-fund
  npm run build
)

mkdir -p node_modules/@kynesyslabs
ln -sfn ../../sdk node_modules/@kynesyslabs/dacs

echo "DACS SDK ${SDK_REV} built and linked"
