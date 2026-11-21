#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${ANDROID_KEYSTORE_BASE64:?}" "${ANDROID_STORE_PASSWORD:?}" "${ANDROID_KEY_PASSWORD:?}"
: "${ANDROID_KEY_ALIAS:?}" "${ANDROID_CERT_SHA256:?}" "${SOURCE_SHA:?}" "${SOURCE_VERSION:?}" "${SOURCE_TAG:?}"
tools="$ANDROID_HOME/build-tools/35.0.0"
stage=$(mktemp -d "$RUNNER_TEMP/apk-sign.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
printf '%s' "$ANDROID_KEYSTORE_BASE64" | base64 --decode >"$stage/release.jks"
unset ANDROID_KEYSTORE_BASE64
(
  cd unsigned
  sha256sum -c SHA256SUMS
)
python3 - "$SOURCE_TAG" "$SOURCE_SHA" "$SOURCE_VERSION" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path("unsigned/BUILD.json").read_text())
assert (data["ref"], data["sha"], data["version"]) == tuple(sys.argv[1:])
assert data["repo"] == "sqeezy-53/school-day" and data["platform"] == "android"
assert data["mode"] in ("prepare", "draft")
PY
input="unsigned/school-day-$SOURCE_VERSION-unsigned.apk"
signed="school-day-$SOURCE_VERSION-android.apk"
python3 ci/verify_apk.py "$input" --tools "$tools" --version "$SOURCE_VERSION" --signature unsigned
mkdir dist
"$tools/zipalign" -P 16 -f 4 "$input" "$stage/aligned.apk"
"$tools/apksigner" sign --ks "$stage/release.jks" --ks-key-alias "$ANDROID_KEY_ALIAS" \
  --ks-pass env:ANDROID_STORE_PASSWORD --key-pass env:ANDROID_KEY_PASSWORD \
  --out "dist/$signed" "$stage/aligned.apk"
"$tools/zipalign" -c -P 16 4 "dist/$signed"
python3 ci/verify_apk.py "dist/$signed" --tools "$tools" --version "$SOURCE_VERSION" \
  --signature release --certificate "$ANDROID_CERT_SHA256" >dist/CERTIFICATE.txt
cp unsigned/BUILD.json "unsigned/school-day-$SOURCE_VERSION-source.tar.gz" dist/
(
  cd dist
  sha256sum "$signed" BUILD.json CERTIFICATE.txt "school-day-$SOURCE_VERSION-source.tar.gz" >SHA256SUMS
  sha256sum -c SHA256SUMS
)
