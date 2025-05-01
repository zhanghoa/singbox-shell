#!/bin/sh

# ======================
# 配置参数
# ======================
TPROXY_PORT=7895
ROUTING_MARK=666
PROXY_FWMARK=1
PROXY_ROUTE_TABLE=100
INTERFACE=$(ip route show default | awk '/default/ {print $5; exit}')

# IP 地址集合
RESERVED_IPS="127.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 198.51.100.0/24 192.88.99.0/24 192.168.0.0/16 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32"
CUSTOM_BYPASS_IPS="192.168.0.0/16 10.0.0.0/8"

# 读取当前模式
MODE=$(grep -E '^MODE=' /etc/sing-box/mode.conf | sed 's/^MODE=//')

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
# 清理函数（兼容 TUN 模式规则）
# ======================
clear_nft_rules() {
    nft list table inet sing-box >/dev/null 2>&1 && nft delete table inet sing-box
    ip rule del fwmark $PROXY_FWMARK lookup $PROXY_ROUTE_TABLE 2>/dev/null
    ip route del local default dev "${INTERFACE}" table $PROXY_ROUTE_TABLE 2>/dev/null
    iptables -t mangle -F SINGBOX 2>/dev/null
    iptables -t mangle -X SINGBOX 2>/dev/null
    echo "🧹 已清理 nftables 的旧规则"
}

clear_iptables_rules() {
    iptables -t mangle -F PREROUTING 2>/dev/null
    iptables -t mangle -F OUTPUT 2>/dev/null
    iptables -t mangle -X SINGBOX 2>/dev/null
    ipset destroy reserved_ips 2>/dev/null
    ipset destroy custom_bypass_ips 2>/dev/null
    ip rule del fwmark $PROXY_FWMARK lookup $PROXY_ROUTE_TABLE 2>/dev/null
    ip route del local default dev "${INTERFACE}" table $PROXY_ROUTE_TABLE 2>/dev/null
    echo "🧹 已清理 iptables 的旧规则"
}

# ======================
# 路由表设置函数（避免重复添加）
# ======================
setup_route_table() {
    # 检查规则是否存在
    ip rule show | grep -q "fwmark $PROXY_FWMARK" || ip rule add fwmark $PROXY_FWMARK lookup $PROXY_ROUTE_TABLE
    ip route show table $PROXY_ROUTE_TABLE | grep -q "default" || ip route add local default dev "$INTERFACE" table $PROXY_ROUTE_TABLE
    echo "✅ 自定义路由表已配置"
}

# ======================
# 开启 IP 转发（通用）
# ======================
enable_ip_forwarding() {
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf 2>/dev/null || true
    sysctl -p > /dev/null
    echo "✅ 已启用 IP 转发"
}

# ======================
# nftables 规则配置（TProxy 模式）
# ======================
setup_nft_rules() {
    cat > /tmp/singbox-nft.conf <<EOF
table inet sing-box {
    set RESERVED_IPSET {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { $RESERVED_IPS }
    }

    set CUSTOM_BYPASS_IPSET {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { $CUSTOM_BYPASS_IPS }
    }

    chain prerouting_tproxy {
        type filter hook prerouting priority mangle; policy accept;

        meta l4proto { tcp, udp } th dport 53 tproxy to :$TPROXY_PORT accept

        ip daddr @CUSTOM_BYPASS_IPSET accept

        fib daddr type local meta l4proto { tcp, udp } th dport $TPROXY_PORT reject with icmpx type host-unreachable

        fib daddr type local accept

        ip daddr @RESERVED_IPSET accept

        ct status dnat accept

        meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_FWMARK
    }

    chain output_tproxy {
        type route hook output priority mangle; policy accept;

        meta oifname "lo" accept

        meta mark $ROUTING_MARK accept

        meta l4proto { tcp, udp } th dport 53 meta mark set $PROXY_FWMARK

        udp dport { netbios-ns, netbios-dgm, netbios-ssn } accept

        ip daddr @CUSTOM_BYPASS_IPSET accept

        fib daddr type local accept

        ip daddr @RESERVED_IPSET accept

        meta l4proto { tcp, udp } meta mark set $PROXY_FWMARK
    }
}
EOF

    nft -f /tmp/singbox-nft.conf
    nft list ruleset > /etc/nftables/tproxy.conf
    echo "✅ 已应用 nftables 的 TProxy 规则"
}

# ======================
# iptables 规则配置（TProxy 模式）
# ======================
setup_iptables_rules() {
    modprobe xt_TPROXY xt_set ip_set xt_conntrack

    ipset create reserved_ips hash:net
    for ip in $RESERVED_IPS; do ipset add reserved_ips $ip; done

    ipset create custom_bypass_ips hash:net
    for ip in $CUSTOM_BYPASS_IPS; do ipset add custom_bypass_ips $ip; done

    iptables -t mangle -A PREROUTING -p tcp --dport 53 -j TPROXY --tproxy-mark 0x$PROXY_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A PREROUTING -p udp --dport 53 -j TPROXY --tproxy-mark 0x$PROXY_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A PREROUTING -m set --match-set custom_bypass_ips dst -j ACCEPT
    iptables -t mangle -A PREROUTING -p tcp --dport $TPROXY_PORT -m addrtype --dst-type LOCAL -j REJECT --reject-with icmp-host-unreachable
    iptables -t mangle -A PREROUTING -p udp --dport $TPROXY_PORT -m addrtype --dst-type LOCAL -j REJECT --reject-with icmp-host-unreachable
    iptables -t mangle -A PREROUTING -m addrtype --dst-type LOCAL -j ACCEPT
    iptables -t mangle -A PREROUTING -m set --match-set reserved_ips dst -j ACCEPT
    iptables -t mangle -A PREROUTING -m conntrack --ctstate DNAT -j ACCEPT
    iptables -t mangle -A PREROUTING -p tcp -j TPROXY --tproxy-mark 0x$PROXY_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A PREROUTING -p udp -j TPROXY --tproxy-mark 0x$PROXY_FWMARK --on-port $TPROXY_PORT

    iptables -t mangle -A OUTPUT -o lo -j ACCEPT
    iptables -t mangle -A OUTPUT -m mark --mark $ROUTING_MARK -j ACCEPT
    iptables -t mangle -A OUTPUT -p tcp --dport 53 -j MARK --set-mark $PROXY_FWMARK
    iptables -t mangle -A OUTPUT -p udp --dport 53 -j MARK --set-mark $PROXY_FWMARK
    iptables -t mangle -A OUTPUT -p udp --dport 137 -j ACCEPT
    iptables -t mangle -A OUTPUT -p udp --dport 138 -j ACCEPT
    iptables -t mangle -A OUTPUT -p tcp --dport 139 -j ACCEPT
    iptables -t mangle -A OUTPUT -m set --match-set custom_bypass_ips dst -j ACCEPT
    iptables -t mangle -A OUTPUT -m addrtype --dst-type LOCAL -j ACCEPT
    iptables -t mangle -A OUTPUT -m set --match-set reserved_ips dst -j ACCEPT
    iptables -t mangle -A OUTPUT -p tcp -j MARK --set-mark $PROXY_FWMARK
    iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark $PROXY_FWMARK

    iptables-save > /etc/iptables/tproxy-rules.v4
    echo "✅ 已应用 iptables 的 TProxy 规则"
}

# ======================
# 主流程开始
# ======================

if [ "$MODE" != "TProxy" ]; then
    echo "ℹ️ 当前不是 TProxy 模式，跳过配置。"
    exit 0
fi

echo "🚀 Sing-Box TProxy 模式自动配置脚本启动..."
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

enable_ip_forwarding
setup_route_table
echo "🎉 TProxy 模式的防火墙规则已成功应用。"
