#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
out="$root/build/apple"
mkdir -p "$out/artifacts"
{ xcodebuild -version; xcodebuild -showsdks; swift --version; xcodegen --version; } | tee "$out/artifacts/toolchain.txt"
xcodegen generate --spec apps/apple/project.yml
xcodebuild -project apps/apple/WatchLogin.xcodeproj -scheme Host -configuration Release -destination 'generic/platform=iOS' -derivedDataPath "$out/DerivedData" CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build | tee "$out/artifacts/build.log"
python3 apps/apple/verify_package.py "$out/DerivedData/Build/Products/Release-iphoneos/Host.app" "$out/artifacts"
