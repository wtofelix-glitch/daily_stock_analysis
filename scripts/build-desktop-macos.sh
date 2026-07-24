#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export ELECTRON_BUILDER_CACHE="${ROOT_DIR}/.electron-builder-cache"

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

distribution_build=false
if is_true "${GITHUB_ACTIONS:-}"; then
  distribution_build=true
elif [[ -n "${DSA_MAC_DISTRIBUTION:-}" ]] &&
  is_true "${DSA_MAC_DISTRIBUTION}"; then
  distribution_build=true
fi

notary_auth_args=()

prepare_distribution_credentials() {
  local available_identities=""
  local api_credentials=0
  local apple_id_credentials=0

  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: signed macOS distribution builds must run on macOS."
    exit 1
  fi

  # electron-builder imports CSC_LINK when supplied. Otherwise require a
  # Developer ID Application identity already installed in the keychain.
  if [[ -n "${CSC_LINK:-}" ]] && [[ -z "${CSC_KEY_PASSWORD:-}" ]]; then
    echo "ERROR: CSC_KEY_PASSWORD is required when CSC_LINK is provided."
    exit 1
  fi
  available_identities="$(security find-identity -v -p codesigning 2>/dev/null || true)"
  if [[ -z "${CSC_LINK:-}" ]] &&
    [[ "${available_identities}" != *"Developer ID Application"* ]]; then
    echo "ERROR: no Developer ID Application signing identity is available."
    echo "Provide CSC_LINK/CSC_KEY_PASSWORD or install the certificate in the build keychain."
    exit 1
  fi

  [[ -n "${APPLE_API_KEY:-}" ]] && api_credentials=$((api_credentials + 1))
  [[ -n "${APPLE_API_KEY_ID:-}" ]] && api_credentials=$((api_credentials + 1))
  [[ -n "${APPLE_API_ISSUER:-}" ]] && api_credentials=$((api_credentials + 1))
  [[ -n "${APPLE_ID:-}" ]] && apple_id_credentials=$((apple_id_credentials + 1))
  [[ -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]] &&
    apple_id_credentials=$((apple_id_credentials + 1))
  [[ -n "${APPLE_TEAM_ID:-}" ]] &&
    apple_id_credentials=$((apple_id_credentials + 1))

  if [[ "${api_credentials}" -ne 0 ]] && [[ "${api_credentials}" -ne 3 ]]; then
    echo "ERROR: App Store Connect API notarization credentials are incomplete."
    echo "Provide APPLE_API_KEY, APPLE_API_KEY_ID, and APPLE_API_ISSUER together."
    exit 1
  fi
  if [[ "${apple_id_credentials}" -ne 0 ]] &&
    [[ "${apple_id_credentials}" -ne 3 ]]; then
    echo "ERROR: Apple ID notarization credentials are incomplete."
    echo "Provide APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, and APPLE_TEAM_ID together."
    exit 1
  fi

  if [[ "${api_credentials}" -eq 3 ]]; then
    if [[ ! -f "${APPLE_API_KEY}" ]] || [[ ! -r "${APPLE_API_KEY}" ]]; then
      echo "ERROR: APPLE_API_KEY must point to a readable App Store Connect .p8 file."
      exit 1
    fi
    notary_auth_args=(
      "--key" "${APPLE_API_KEY}"
      "--key-id" "${APPLE_API_KEY_ID}"
      "--issuer" "${APPLE_API_ISSUER}"
    )
  elif [[ "${apple_id_credentials}" -eq 3 ]]; then
    notary_auth_args=(
      "--apple-id" "${APPLE_ID}"
      "--password" "${APPLE_APP_SPECIFIC_PASSWORD}"
      "--team-id" "${APPLE_TEAM_ID}"
    )
  else
    echo "ERROR: Apple notarization credentials are incomplete."
    echo "Provide APPLE_API_KEY/APPLE_API_KEY_ID/APPLE_API_ISSUER or"
    echo "APPLE_ID/APPLE_APP_SPECIFIC_PASSWORD/APPLE_TEAM_ID."
    exit 1
  fi

  # Override stale local/runner values that previously disabled signing.
  export CSC_IDENTITY_AUTO_DISCOVERY="true"
}

find_single_artifact() {
  local artifact_name="$1"
  local artifact_pattern="$2"
  local found=""
  local count=0
  local candidate

  while IFS= read -r candidate; do
    found="${candidate}"
    count=$((count + 1))
  done < <(find dist -maxdepth 2 -type "${artifact_name}" -name "${artifact_pattern}" -print)

  if [[ "${count}" -ne 1 ]]; then
    echo "ERROR: expected one ${artifact_pattern} artifact, found ${count}." >&2
    exit 1
  fi

  printf '%s\n' "${found}"
}

verify_signed_app() {
  local app_path="$1"
  local component

  echo "Verifying nested macOS bundle signatures..."
  while IFS= read -r component; do
    if ! codesign --verify --strict --verbose=4 "${component}"; then
      echo "ERROR: first invalid nested bundle signature after Electron packaging: ${component}"
      exit 1
    fi
  done < <(
    find "${app_path}" -depth -type d \
      \( -name "*.app" -o -name "*.framework" -o -name "*.xpc" \) \
      ! -path "${app_path}" -print
  )

  echo "Verifying nested macOS executable signatures..."
  while IFS= read -r component; do
    if file -b "${component}" | grep -q "Mach-O"; then
      if ! codesign --verify --strict --verbose=4 "${component}"; then
        echo "ERROR: first invalid nested signature after Electron packaging: ${component}"
        exit 1
      fi
    fi
  done < <(find "${app_path}" -type f -print)

  echo "Verifying final application signature..."
  if ! codesign --verify --deep --strict --verbose=4 "${app_path}"; then
    echo "ERROR: application signature chain is invalid after Electron packaging: ${app_path}"
    exit 1
  fi
  if ! codesign -dv --verbose=4 "${app_path}" 2>&1 |
    grep -q "^Authority=Developer ID Application:"; then
    echo "ERROR: application is not signed with a Developer ID Application identity: ${app_path}"
    exit 1
  fi
}

notarize_and_verify_dmg() {
  local dmg_path="$1"
  local mount_dir
  local mounted_app
  local is_mounted=false

  echo "Submitting DMG for Apple notarization..."
  xcrun notarytool submit "${dmg_path}" --wait "${notary_auth_args[@]}"

  echo "Stapling and validating the notarization ticket..."
  xcrun stapler staple "${dmg_path}"
  xcrun stapler validate "${dmg_path}"

  mount_dir="$(mktemp -d "${TMPDIR:-/tmp}/dsa-macos-verify.XXXXXX")"
  cleanup_mount() {
    if [[ "${is_mounted}" == "true" ]]; then
      hdiutil detach "${mount_dir}" >/dev/null || true
    fi
    rmdir "${mount_dir}" 2>/dev/null || true
  }
  trap cleanup_mount EXIT

  echo "Mounting notarized DMG for final Gatekeeper assessment..."
  hdiutil attach "${dmg_path}" -nobrowse -readonly -mountpoint "${mount_dir}" >/dev/null
  is_mounted=true
  mounted_app="${mount_dir}/Daily Stock Analysis.app"
  if [[ ! -d "${mounted_app}" ]]; then
    echo "ERROR: application bundle not found in mounted DMG: ${mounted_app}"
    exit 1
  fi

  codesign --verify --deep --strict --verbose=4 "${mounted_app}"
  spctl --assess --type execute --verbose=4 "${mounted_app}"
  if ! hdiutil detach "${mount_dir}" >/dev/null; then
    echo "ERROR: could not detach verification DMG mount: ${mount_dir}"
    exit 1
  fi
  is_mounted=false
  rmdir "${mount_dir}"
  trap - EXIT
}

package_lock_hash() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 package-lock.json | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum package-lock.json | awk '{print $1}'
  else
    echo "No SHA-256 checksum tool found. Install shasum or sha256sum." >&2
    exit 1
  fi
}

install_desktop_dependencies() {
  local reason="$1"

  echo "Installing desktop dependencies (${reason})..."
  npm install
  mkdir -p node_modules
  package_lock_hash > node_modules/.dsa-package-lock.sha256
}

ensure_desktop_dependencies() {
  local marker="node_modules/.dsa-package-lock.sha256"
  local reason=""

  if [[ ! -d node_modules ]]; then
    reason="node_modules missing"
  elif [[ ! -f "${marker}" ]]; then
    reason="package-lock marker missing"
  elif [[ "$(tr -d '[:space:]' < "${marker}")" != "$(package_lock_hash)" ]]; then
    reason="package-lock.json changed"
  elif [[ ! -d node_modules/electron-updater ]]; then
    reason="electron-updater missing"
  fi

  if [[ -n "${reason}" ]]; then
    install_desktop_dependencies "${reason}"
  else
    echo "Desktop dependencies are up to date."
  fi
}

main() {
  echo "Building Electron desktop app (macOS)..."

  if [[ ! -d "${ROOT_DIR}/dist/backend/stock_analysis" ]]; then
    echo "Backend artifact not found: ${ROOT_DIR}/dist/backend/stock_analysis"
    echo "Run scripts/build-backend-macos.sh first."
    exit 1
  fi

  if [[ "${distribution_build}" == "true" ]]; then
    prepare_distribution_credentials
  else
    # Keep local developer packaging available without Apple credentials. These
    # artifacts are explicitly non-distributable and skip all release assertions.
    export CSC_IDENTITY_AUTO_DISCOVERY="false"
    echo "WARNING: unsigned local macOS build; do not publish this artifact."
    echo "Set DSA_MAC_DISTRIBUTION=true and provide Apple credentials for a release build."
  fi

  pushd "${ROOT_DIR}/apps/dsa-desktop" >/dev/null

  ensure_desktop_dependencies

  if compgen -G "dist/mac*" >/dev/null; then
    echo "Cleaning dist/mac*..."
    rm -rf dist/mac*
  fi
  if compgen -G "dist/*.dmg" >/dev/null; then
    echo "Cleaning stale dist/*.dmg..."
    rm -f dist/*.dmg
  fi

  MAC_ARCH="${DSA_MAC_ARCH:-}"
  ARCH_ARGS=()
  BUILDER_ARGS=()
  if [[ -n "${MAC_ARCH}" ]]; then
    case "${MAC_ARCH}" in
      x64|arm64)
        ARCH_ARGS+=("--${MAC_ARCH}")
        ;;
      *)
        echo "Unsupported DSA_MAC_ARCH: ${MAC_ARCH}. Use x64 or arm64."
        exit 1
        ;;
    esac
  fi
  if [[ "${distribution_build}" == "true" ]]; then
    BUILDER_ARGS+=("--config.forceCodeSigning=true")
  fi

  echo "Building macOS target arch: ${MAC_ARCH:-default}"
  if [[ ${#ARCH_ARGS[@]} -gt 0 ]]; then
    npx electron-builder --mac dmg "${ARCH_ARGS[@]}" "${BUILDER_ARGS[@]}" --publish never
  else
    npx electron-builder --mac dmg "${BUILDER_ARGS[@]}" --publish never
  fi

  if [[ "${distribution_build}" == "true" ]]; then
    app_path="$(find_single_artifact d "Daily Stock Analysis.app")"
    dmg_path="$(find_single_artifact f "*.dmg")"
    verify_signed_app "${app_path}"
    notarize_and_verify_dmg "${dmg_path}"
  fi
  popd >/dev/null

  echo "Desktop build completed."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
