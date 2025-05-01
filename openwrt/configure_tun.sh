#!/bin/bash

# ======================
# 配置参数
# ======================
PROXY_FWMARK=1
PROXY_ROUTE_TABLE=100
TUN_INTERFACE="tun0"
LAN_INTERFACE=$(ip route show default | awk '/default/ {print $5}') # 默认网卡，如 br-lan

# 读取模式配置（TUN 或 TProxy）
MODE=$(grep -E '^MODE=' /etc/sing-box/mode.conf | sed 's/^MODE=//')

# ======================
# 清理函数定义（按防火墙类型分开）
# ======================

clear_nft_rules() {
    nft list table inet sing-box >/dev/null 2>&1 && nft delete table inet sing-box
    ip rule del fwmark $PROXY_FWMARK lookup $PROXY_ROUTE_TABLE 2>/dev/null
    ip route del local default dev "$TUN_INTERFACE" table $PROXY_ROUTE_TABLE 2>/dev/null
    echo "🧹 已清理 nftables 的旧规则"
}

clear_iptables_rules() {
    iptables -t mangle -F SINGBOX 2>/dev/null
    iptables -t mangle -X SINGBOX 2>/dev/null
    iptables -t mangle -D PREROUTING -i "$LAN_INTERFACE" -j SINGBOX 2>/dev/null
    iptables -D FORWARD -i "$LAN_INTERFACE" -o "$TUN_INTERFACE" -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -o "$TUN_INTERFACE" -j MASQUERADE 2>/dev/null
    ip rule del fwmark $PROXY_FWMARK lookup $PROXY_ROUTE_TABLE 2>/dev/null
    ip route del local default dev "$TUN_INTERFACE" table $PROXY_ROUTE_TABLE 2>/dev/null
    echo "🧹 已清理 iptables 的旧规则"
}

# ======================
# 设置函数定义
# ======================

setup_nft_rules() {
    cat > /tmp/singbox-nft.conf <<EOF
table inet sing-box {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    nft -f /tmp/singbox-nft.conf
    nft list ruleset > /etc/nftables.conf
    echo "✅ 已应用 nftables 规则"
}

setup_iptables_rules() {
    # 创建自定义链并设置流量标记
    iptables -t mangle -N SINGBOX 2>/dev/null
    iptables -t mangle -A PREROUTING -i "$LAN_INTERFACE" -j SINGBOX

    # 忽略局域网 IP 地址
    iptables -t mangle -A SINGBOX -d 0.0.0.0/8 -j RETURN
    iptables -t mangle -A SINGBOX -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A SINGBOX -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A SINGBOX -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A SINGBOX -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A SINGBOX -d 240.0.0.0/4 -j RETURN

    # 打上 fwmark 标记
    iptables -t mangle -A SINGBOX -j MARK --set-mark $PROXY_FWMARK
    iptables -t mangle -A SINGBOX -j CONNMARK --save-mark

    # 放行 tun 接口上的流量
    iptables -I FORWARD -i "$LAN_INTERFACE" -o "$TUN_INTERFACE" -j ACCEPT
    iptables -I FORWARD -i "$TUN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -o "$TUN_INTERFACE" -j MASQUERADE

    echo "✅ 已应用 iptables 规则"
}

# ======================
# 路由表设置通用函数
# ======================
setup_route_table() {
    ip rule add fwmark $PROXY_FWMARK lookup $PROXY_ROUTE_TABLE
    ip route add local default dev "$TUN_INTERFACE" table $PROXY_ROUTE_TABLE
    echo "✅ 自定义路由表已配置"
}

# ======================
# 防火墙类型检测函数
# ======================
detect_firewall_backend() {
    if command -v iptables >/dev/null 2>&1; then
        IPTABLES_VERSION=$(iptables --version 2>&1)
        if [[ "$IPTABLES_VERSION" == *"nf_tables"* ]]; then
            echo "nftables"
        else
            echo "iptables-legacy"
        fi
    else
        echo "未安装 iptables"
    fi
}

# ======================
# 主流程开始
# ======================
echo "🚀 Sing-Box TUN 模式自动配置脚本启动..."

if [ "$MODE" != "TUN" ]; then
    echo "ℹ️ 当前不是 TUN 模式，跳过防火墙规则配置。" >/dev/null 2>&1
    exit 0
fi

echo "⚙️ 正在检测防火墙类型..."
FIREWALL_TYPE=$(detect_firewall_backend)

case "$FIREWALL_TYPE" in
    "nftables")
        echo "🔥 当前使用 nftables 后端"
        clear_nft_rules
        setup_nft_rules
        ;;
    "iptables-legacy")
        echo "🔥 当前使用 legacy iptables 后端"
        clear_iptables_rules
        setup_iptables_rules
        ;;
    *)
        echo "⚠️ 无法识别防火墙类型，退出"
        exit 1
        ;;
esac

setup_route_table
echo "🎉 TUN 模式的防火墙规则已成功应用。"
