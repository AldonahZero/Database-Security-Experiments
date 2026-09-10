#!/bin/bash

# --- 配置 ---
# Clash 的 Controller API 地址和端口
CLASH_API="http://127.0.0.1:19090"
# 全局代理策略组的名称，通常是 GLOBAL，也可能是 PROXY 或其他，请根据你的配置文件修改
POLICY_GROUP="proxies"

# --- 脚本主体 ---

# 函数：用于切换 Clash 节点
switch_proxy() {
  local node_name="$1"
  # URL 编码节点名称，防止特殊字符导致请求失败
  local encoded_node_name=$(printf %s "$node_name" | jq -s -R -r @uri)
  curl -s -o /dev/null -X PUT "${CLASH_API}/proxies/${POLICY_GROUP}" \
       -H "Content-Type: application/json" \
       -d "{\"name\": \"${node_name}\"}"
  echo "已切换到节点: $node_name"
}

# 1. 获取所有真实代理节点的名称 (排除内置策略和策略组)
# 这里通过检查 `type` 字段来筛选出真实的代理节点
echo "正在从 Clash API 获取节点列表..."
NODES=$(curl -s "${CLASH_API}/proxies" | jq -r '.proxies | to_entries[] | select(.value.type | test("^(ss|ssr|vmess|trojan|vless|socks5|http)$")) | .key')

if [ -z "$NODES" ]; then
  echo "错误：无法获取到节点列表，请检查 Clash API 地址或配置文件。"
  exit 1
fi

echo "获取到以下节点，准备开始测速："
echo "$NODES"
echo "========================================="

# 2. 循环测试每个节点
for NODE in $NODES; do
  echo ""
  echo "--- [正在测试节点: $NODE] ---"

  # 切换代理
  switch_proxy "$NODE"
  # 等待1-2秒确保切换生效
  sleep 2

  # 执行速度测试
  # 使用 speedtest-cli 的 --simple 参数可以输出更简洁的结果
  # 你也可以移除 --simple 来获取更详细的信息
  echo "正在运行 Speedtest.net ..."
  speedtest-cli --simple

  echo "-----------------------------------------"
done

echo "全部节点测试完毕。"

# 脚本结束后，你可以选择切换回一个默认的节点，或者切换到自动选择模式
# switch_proxy "自动选择"