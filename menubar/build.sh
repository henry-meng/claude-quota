#!/usr/bin/env bash
#
# Builds Claude Quota Bar into ./build/Claude Quota Bar.app.
#
# Installing is ../install.sh's job. This only ever builds.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_NAME="Claude Quota Bar"
BUILD_DIR="$SCRIPT_DIR/build"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"

if ! command -v swift >/dev/null 2>&1; then
    echo "error: swift not found. Install the Xcode command line tools:" >&2
    echo "         xcode-select --install" >&2
    exit 1
fi

echo "==> Building (release)"
swift build -c release --disable-sandbox

BINARY="$(swift build -c release --show-bin-path)/ClaudeQuotaBar"
if [[ ! -x "$BINARY" ]]; then
    echo "error: build succeeded but no binary at $BINARY" >&2
    exit 1
fi

echo "==> Assembling $APP_NAME.app"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

cp "$BINARY" "$APP_BUNDLE/Contents/MacOS/ClaudeQuotaBar"
cp "$SCRIPT_DIR/Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
printf 'APPL????' > "$APP_BUNDLE/Contents/PkgInfo"

# Sign with a real identity when one exists, ad-hoc otherwise.
#
# This matters beyond Gatekeeper. macOS scopes Keychain access to a specific
# signature, and an ad-hoc signature has no stable identity: its hash changes
# on every build, so "Always Allow" never sticks and the app is re-prompted for
# access to Claude Code's credential after each reinstall. Any real certificate
# fixes that, including a plain Apple Development one.
#
# Override with CODESIGN_IDENTITY. No --deep: Apple deprecated it, and there is
# nothing nested to sign here.
# `|| true` on both: under `set -e` an assignment takes the exit status of the
# command substitution, so a grep that matches nothing kills the script.
find_identity() {
    security find-identity -v -p codesigning 2>/dev/null \
        | grep -m1 "$1" | sed 's/.*"\(.*\)"/\1/' || true
}

if [[ -z "${CODESIGN_IDENTITY:-}" ]]; then
    CODESIGN_IDENTITY="$(find_identity "Developer ID Application")"
fi
if [[ -z "${CODESIGN_IDENTITY:-}" ]]; then
    CODESIGN_IDENTITY="$(find_identity "Apple Development")"
fi

if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
    echo "==> Signing as $CODESIGN_IDENTITY"
    codesign --force --sign "$CODESIGN_IDENTITY" --timestamp=none "$APP_BUNDLE"
else
    echo "==> Signing (ad-hoc; no certificate found)"
    echo "    macOS will re-ask for Keychain access after every rebuild."
    codesign --force --sign - "$APP_BUNDLE"
fi

# Print what actually got used. Silently falling back to ad-hoc is how the
# Keychain re-prompting comes back.
codesign -dvv "$APP_BUNDLE" 2>&1 | grep -E "^Authority|^Signature" | sed 's/^/    /' || true

echo "==> Built: $APP_BUNDLE"
