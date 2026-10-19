#!/bin/sh
set -e

PKG="luci-app-clientstatus_package"
ARCHIVE="${PKG}.tar.gz"
TMP_DIR="/tmp/${PKG}"
URL="https://raw.githubusercontent.com/lianzeliu/luci-app-clientstatus/main/${ARCHIVE}"

echo "== 创建临时目录..."
mkdir -p "${TMP_DIR}"

echo "== 下载安装包..."
wget -O "/tmp/${ARCHIVE}" "${URL}"

echo "== 解压到临时目录..."
tar -xzf "/tmp/${ARCHIVE}" -C /tmp/

echo "== 执行安装脚本..."
chmod +x "$TMP_DIR/install.sh"
$TMP_DIR/install.sh

rm -rf "${TMP_DIR}" "/tmp/${ARCHIVE}"
echo "== 完成 ✅ =="
