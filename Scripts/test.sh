#!/bin/bash
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$task_root"
bash Scripts/prepare-openssl.sh
export CLANG_MODULE_CACHE_PATH="$task_root/work/ModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$task_root/work/ModuleCache"
swift run --cache-path "$task_root/work/SwiftPMCache" CryptoSelfTests
