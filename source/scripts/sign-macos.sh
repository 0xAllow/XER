#!/usr/bin/env bash
# Run on a macOS signing machine with a valid Developer ID Application identity.
# Usage: bash scripts/sign-macos.sh DIST/XER-arm64.app "Developer ID Application: Publisher (TEAMID)"
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Requires macOS' >&2; exit 1; }
[[ $# -eq 2 ]] || { echo 'usage: sign-macos.sh APP_BUNDLE DEVELOPER_ID_IDENTITY' >&2; exit 2; }
codesign --force --options runtime --timestamp --sign "$2" "$1"
codesign --verify --deep --strict --verbose=2 "$1"
echo 'Developer ID signature verified. For distribution, submit for notarization with xcrun notarytool.'
