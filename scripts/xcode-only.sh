#!/usr/bin/env bash
# No Unity installation, Unity license or Apple signing credential is needed here.
set -euo pipefail
kit_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
export_path=""; output=""; resume=0
usage() { printf '%s\n' 'Usage: bash xcode-only.sh --export-path /absolute/Xcode --output /absolute/build-output [--resume]' 'Produces an UNSIGNED IPA. Device installation requires a later signing step.'; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --export-path|--output) [[ $# -ge 2 ]] || die "Missing value for $1"; case "$1" in --export-path) export_path="$2";; --output) output="$2";; esac; shift 2;;
    --resume) resume=1; shift;;
    --help|-h) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done
[[ -n "$export_path" && -n "$output" ]] || { usage >&2; exit 1; }
[[ "$(uname -s)" == Darwin ]] || die 'Xcode compilation requires macOS.'
command -v python3 >/dev/null || die 'Python 3 is required for standard-library artifact validation.'
command -v xcodebuild >/dev/null || die 'Install/select full Xcode with xcode-select.'
command -v ditto >/dev/null || die 'macOS ditto is required.'
export_path="$(cd -- "$export_path" && pwd -P)"
mkdir -p -- "$output"; output="$(cd -- "$output" && pwd -P)"
case "$output/" in "$export_path/"*) die 'Output must not be inside the exported Xcode source.';; esac
case "$export_path/" in "$output/"*) die 'Xcode export must not be inside this Xcode-only output directory.';; esac
lock="$output/.xcode-build.lock"
mkdir -- "$lock" 2>/dev/null || die "Build lock exists: $lock. Inspect its owner before recovering a stale lock."
printf '%s\n' "pid=$$" > "$lock/owner.txt"
stage=""
cleanup() {
  if [[ -n "$stage" && "$stage" == "$output"/package.* && -d "$stage" ]]; then rm -rf -- "$stage"; fi
  rm -f -- "$lock/owner.txt"; rmdir -- "$lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p -- "$output/logs"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
python3 "$kit_dir/ios_artifact.py" export "$export_path" > "$output/logs/export-validation-$stamp.json"
xcodebuild -version > "$output/logs/xcode-version-$stamp.txt"
xcrun --sdk iphoneos --show-sdk-version > "$output/logs/iphoneos-sdk-$stamp.txt"
state="$output/xcode-complete.json"
archive="$output/Salasasa.xcarchive"
if [[ -f "$state" ]]; then
  [[ "$resume" == 1 ]] || die 'Completed build exists; use --resume or a new output directory.'
  python3 "$kit_dir/ios_artifact.py" state-check "$state" --export-path "$export_path" > "$output/logs/resume-validation-$stamp.json"
  app="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["app"]["app"])' "$state")"
else
  if [[ -d "$archive" ]]; then
    [[ "$resume" == 1 ]] || die 'Partial archive exists; use --resume or a new output directory.'
    mv -- "$archive" "$output/Salasasa-incomplete-$stamp.xcarchive"
  fi
  # pipefail preserves a failing xcodebuild status; no archive/IPA success is inferred from log text.
  xcodebuild -project "$export_path/Unity-iPhone.xcodeproj" -scheme Unity-iPhone \
    -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
    -derivedDataPath "$output/DerivedData" -archivePath "$archive" \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= DEVELOPMENT_TEAM= \
    archive 2>&1 | tee "$output/logs/xcode-archive-$stamp.log"
  shopt -s nullglob
  apps=("$archive/Products/Applications/"*.app)
  [[ ${#apps[@]} -eq 1 ]] || die 'Archive did not contain exactly one application.'
  app="${apps[0]}"
  python3 "$kit_dir/ios_artifact.py" app "$app" > "$output/logs/app-validation-$stamp.json"
  python3 "$kit_dir/ios_artifact.py" state-write "$state" --export-path "$export_path" --app-path "$app" > "$output/logs/build-state-$stamp.json"
fi
stage="$(mktemp -d "$output/package.XXXXXX")"
mkdir -- "$stage/Payload"
ditto "$app" "$stage/Payload/$(basename -- "$app")"
ipa="$output/Salasasa-0.5.89-release34-unsigned.ipa"
temporary="$stage/unsigned.ipa"
ditto -c -k --sequesterRsrc --keepParent "$stage/Payload" "$temporary"
python3 "$kit_dir/ios_artifact.py" ipa "$temporary" > "$output/logs/ipa-validation-$stamp.json"
mv -f -- "$temporary" "$ipa"
python3 "$kit_dir/ios_artifact.py" ipa "$ipa" --json-output "$output/unsigned-ipa.json"
(cd -- "$output" && shasum -a 256 "$(basename -- "$ipa")") > "$ipa.sha256"
printf '\nUNSIGNED IPA CREATED: %s\nSHA256: %s\n' "$ipa" "$ipa.sha256"
printf '%s\n' 'This is not installable until signed. No Apple account or signing credential was used.'
