#!/usr/bin/env bash
# Push the prepared UI changes and attach the signed APK to its GitHub release.
# Usage: bash scripts/publish-android.sh [path/to/ScamShield.apk]
set -euo pipefail
android_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$android_script_dir/.."
android_apk_path="${1:-android/ScamShield.apk}"
[ -s "$android_apk_path" ] || { echo "APK not found: $android_apk_path" >&2; exit 1; }
command -v gh >/dev/null || { echo "GitHub CLI (gh) is required." >&2; exit 1; }
android_release_dir="$(mktemp -d "${TMPDIR:-/tmp}/scamshield-release.XXXXXX")"
trap 'rm -rf "$android_release_dir"' EXIT
cp "$android_apk_path" "$android_release_dir/ScamShield.apk"
(cd "$android_release_dir" && shasum -a 256 ScamShield.apk > ScamShield.apk.sha256)
git push origin main
gh release create android-v1.0.0 \
  "$android_release_dir/ScamShield.apk" "$android_release_dir/ScamShield.apk.sha256" \
  --repo BhupendraSharma-eng/scamshield --target main \
  --title "ScamShield for Android 1.0" --notes-file android/RELEASE_NOTES.md
printf '%s\n' 'Published: https://github.com/BhupendraSharma-eng/scamshield/releases/download/android-v1.0.0/ScamShield.apk'
