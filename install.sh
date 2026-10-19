#!/bin/sh
# clientstatus 一键安装脚本 v20261019-2
# 用法:
#   sh install.sh           # 安装
#   sh install.sh uninstall # 卸载
set -e

ACTION="${1:-install}"

PKG="luci-app-clientstatus_package"
ARCHIVE="${PKG}.tar.gz"
TMP_DIR="/tmp/${PKG}"
URL="https://raw.githubusercontent.com/lianzeliu/luci-app-clientstatus/main/${ARCHIVE}"

echo "== [v20261019-2] 下载安装包..."
echo "URL: $URL"
rm -rf "${TMP_DIR}" "/tmp/${ARCHIVE}"
mkdir -p "${TMP_DIR}"
if command -v wget >/dev/null 2>&1; then
    echo "用 wget 下载..."
    wget -O "/tmp/${ARCHIVE}" "${URL}" || {
        echo "wget 失败, 试 curl..."
        curl -L -o "/tmp/${ARCHIVE}" "${URL}"
    }
elif command -v curl >/dev/null 2>&1; then
    echo "用 curl 下载..."
    curl -L -o "/tmp/${ARCHIVE}" "${URL}"
else
    echo "错误: 找不到 wget 或 curl"
    exit 1
fi

if [ ! -s "/tmp/${ARCHIVE}" ]; then
    echo "错误: 下载失败, 文件为空或不存在"
    exit 1
fi
echo "下载成功, 大小: $(ls -lh /tmp/${ARCHIVE} | awk '{print $5}')"

echo "== 解压..."
tar -xzf "/tmp/${ARCHIVE}" -C /tmp/
echo "解压完成, 内容:"
ls -lh "$TMP_DIR" | head -10

echo "== 执行安装..."
chmod +x "$TMP_DIR/install.sh"
"$TMP_DIR/install.sh" "$ACTION"

rm -rf "${TMP_DIR}" "/tmp/${ARCHIVE}"
echo "== 完成 ✅ =="
