#!/bin/bash
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
task_version="3.5.9"
task_sha256="603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
task_arch="$(uname -m)"
case "$task_arch" in
    arm64) task_target="darwin64-arm64-cc" ;;
    x86_64) task_target="darwin64-x86_64-cc" ;;
    *) echo "不支持的架构: $task_arch" >&2; exit 1 ;;
esac
task_prefix="$task_root/Vendor/openssl"
task_stamp="$task_version-$task_arch-macos14"
if [[ -f "$task_prefix/.cipherdesk-build" ]] && [[ "$(cat "$task_prefix/.cipherdesk-build")" == "$task_stamp" ]] && [[ -f "$task_prefix/lib/libcrypto.a" ]]; then
    echo "OpenSSL $task_version ($task_arch) 已就绪"
    exit 0
fi
mkdir -p "$task_root/work"
task_archive="$task_root/work/openssl-source.tar.gz"
if [[ ! -f "$task_archive" ]] || [[ "$(shasum -a 256 "$task_archive" | cut -d ' ' -f 1)" != "$task_sha256" ]]; then
    echo "下载 OpenSSL ${task_version}；仅下载公开源代码"
    curl --fail --location --continue-at - --connect-timeout 20 --max-time 1800 \
        "https://github.com/openssl/openssl/releases/download/openssl-$task_version/openssl-$task_version.tar.gz" --output "$task_archive"
fi
if [[ "$(shasum -a 256 "$task_archive" | cut -d ' ' -f 1)" != "$task_sha256" ]]; then
    echo "OpenSSL 源码 SHA256 不匹配，已停止。请移走损坏的 work/openssl-source.tar.gz 后重试。" >&2
    exit 1
fi
tar -xzf "$task_archive" -C "$task_root/work"
cd "$task_root/work/openssl-$task_version"
echo "编译 OpenSSL ${task_version}，目标 $task_arch / macOS 14+"
./Configure "$task_target" no-shared no-module no-tests no-apps no-docs no-ssl no-quic \
    --prefix="$task_prefix" --libdir=lib -mmacosx-version-min=14.0 > "$task_root/work/openssl-configure.log" 2>&1
make -j 6 build_libs > "$task_root/work/openssl-build.log" 2>&1
make install_dev > "$task_root/work/openssl-install.log" 2>&1
cp LICENSE.txt "$task_prefix/LICENSE.txt"
printf '%s\n' "$task_stamp" > "$task_prefix/.cipherdesk-build"
echo "OpenSSL 静态库编译完成"
