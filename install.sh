#!/bin/sh
# clientstatus 一键安装脚本
# 用法:
#   sh install.sh           # 安装
#   sh install.sh uninstall # 卸载
set -e

ACTION="${1:-install}"

PKG="luci-app-clientstatus_package"
ARCHIVE="${PKG}.tar.gz"
TMP_DIR="/tmp/${PKG}"
URL="https://raw.githubusercontent.com/lianzeliu/luci-app-clientstatus/main/${ARCHIVE}"

echo "== 下载安装包..."
rm -rf "${TMP_DIR}" "/tmp/${ARCHIVE}"
mkdir -p "${TMP_DIR}"
wget -O "/tmp/${ARCHIVE}" "${URL}" || curl -L -o "/tmp/${ARCHIVE}" "${URL}"

echo "== 解压..."
tar -xzf "/tmp/${ARCHIVE}" -C /tmp/

echo "== 执行安装..."
chmod +x "$TMP_DIR/install.sh"
"$TMP_DIR/install.sh" "$ACTION"

rm -rf "${TMP_DIR}" "/tmp/${ARCHIVE}"
echo "== 完成 ✅ =="
