#!/bin/bash
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$task_root"
bash Scripts/prepare-openssl.sh
export CLANG_MODULE_CACHE_PATH="$task_root/work/ModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$task_root/work/ModuleCache"
swift build -c release --product CipherDesk --cache-path "$task_root/work/SwiftPMCache"
mkdir -p "$task_root/build"
task_stage="$(mktemp -d "$task_root/work/app-build.XXXXXX")"
task_app="$task_stage/加解密工具.app"
task_destination="$task_root/build/加解密工具.app"
mkdir -p "$task_app/Contents/MacOS" "$task_app/Contents/Resources"
cp .build/release/CipherDesk "$task_app/Contents/MacOS/CipherDesk"
cp Vendor/openssl/LICENSE.txt "$task_app/Contents/Resources/OpenSSL-LICENSE.txt"
swift -module-cache-path "$task_root/work/ModuleCache" Scripts/MakeIcon.swift "$task_root/work/AppIcon.iconset"
iconutil -c icns "$task_root/work/AppIcon.iconset" -o "$task_app/Contents/Resources/AppIcon.icns"
python3 - "$task_app/Contents/Info.plist" <<'PY'
import plistlib, sys
with open(sys.argv[1], 'wb') as f:
    plistlib.dump({
        'CFBundleName': '加解密工具', 'CFBundleDisplayName': '加解密工具',
        'CFBundleIdentifier': 'cn.mky.CipherDesk', 'CFBundleExecutable': 'CipherDesk',
        'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': '1.1.0',
        'CFBundleVersion': '2', 'CFBundleIconFile': 'AppIcon',
        'LSMinimumSystemVersion': '14.0', 'LSApplicationCategoryType': 'public.app-category.developer-tools',
        'NSHighResolutionCapable': True, 'NSSupportsAutomaticTermination': False
    }, f, sort_keys=True)
PY
codesign --force --sign "${CIPHERDESK_SIGN_IDENTITY:--}" "$task_app"
codesign --verify --strict "$task_app"
# Stage the whole bundle before replacing its directory, so an existing process
# can continue using its original executable and keep any unsaved input.
python3 - "$task_app" "$task_destination" "$task_stage/previous.app" <<'PY'
from pathlib import Path
import os, sys
source, target, previous = map(Path, sys.argv[1:])
if target.exists():
    os.rename(target, previous)
try:
    os.rename(source, target)
except OSError:
    if previous.exists() and not target.exists():
        os.rename(previous, target)
    raise
PY
codesign --verify --strict "$task_destination"
echo "构建完成: $task_destination"
