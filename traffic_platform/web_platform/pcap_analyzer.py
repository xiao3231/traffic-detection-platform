#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PCAP 文件分析工具
提供详细的协议分布、流量统计、连接分析等功能
"""

import sys
import os
from collections import Counter, defaultdict
from datetime import datetime

def analyze_pcap(pcap_path):
    """分析 PCAP 文件，返回详细的统计信息"""
    try:
        from scapy.all import rdpcap, TCP, UDP, IP, ICMP, ARP, DNS, HTTP
    except ImportError:
        print("错误：请先安装 scapy: pip install scapy")
        sys.exit(1)

    if not os.path.exists(pcap_path):
        print(f"错误：文件不存在 {pcap_path}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  PCAP 文件分析报告")
    print(f"{'='*60}")
    print(f"文件路径: {pcap_path}")
    print(f"文件大小: {os.path.getsize(pcap_path) / 1024:.2f} KB")
    print(f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    packets = rdpcap(pcap_path)
    total = len(packets)

    # ========== 基础统计 ==========
    stats = {
        'total': total,
        'tcp': 0,
        'udp': 0,
        'icmp': 0,
        'arp': 0,
        'other': 0,
        'http': 0,
        'https': 0,
        'dns': 0,
        'ftp': 0,
        'ssh': 0,
        'smtp': 0,
    }

    # IP 统计
    src_ips = Counter()
    dst_ips = Counter()
    src_ports = Counter()
    dst_ports = Counter()

    # 连接跟踪
    connections = set()
    packet_sizes = []
    timestamps = []

    for pkt in packets:
        packet_sizes.append(len(pkt))
        if hasattr(pkt, 'time'):
            timestamps.append(float(pkt.time))

        # 协议识别
        if pkt.haslayer(TCP):
            stats['tcp'] += 1
            tcp = pkt[TCP]
            src_ports[tcp.sport] += 1
            dst_ports[tcp.dport] += 1

            # 应用层识别
            if tcp.dport == 80 or tcp.sport == 80:
                stats['http'] += 1
            elif tcp.dport == 443 or tcp.sport == 443:
                stats['https'] += 1
            elif tcp.dport == 21 or tcp.sport == 21:
                stats['ftp'] += 1
            elif tcp.dport == 22 or tcp.sport == 22:
                stats['ssh'] += 1
            elif tcp.dport == 25 or tcp.sport == 25:
                stats['smtp'] += 1

            # 连接跟踪
            if pkt.haslayer(IP):
                ip = pkt[IP]
                conn = tuple(sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)]))
                connections.add(conn)
                src_ips[ip.src] += 1
                dst_ips[ip.dst] += 1

        elif pkt.haslayer(UDP):
            stats['udp'] += 1
            udp = pkt[UDP]
            src_ports[udp.sport] += 1
            dst_ports[udp.dport] += 1

            if pkt.haslayer(DNS):
                stats['dns'] += 1

            if pkt.haslayer(IP):
                ip = pkt[IP]
                src_ips[ip.src] += 1
                dst_ips[ip.dst] += 1

        elif pkt.haslayer(ICMP):
            stats['icmp'] += 1
        elif pkt.haslayer(ARP):
            stats['arp'] += 1
        else:
            stats['other'] += 1

    # ========== 输出报告 ==========

    # 1. 协议分布
    print("【协议分布】")
    print("-" * 40)
    protocols = [
        ('TCP', stats['tcp']),
        ('UDP', stats['udp']),
        ('ICMP', stats['icmp']),
        ('ARP', stats['arp']),
        ('Other', stats['other']),
    ]
    for name, count in protocols:
        pct = count / total * 100 if total else 0
        bar = '█' * int(pct / 2)
        print(f"  {name:8s} {count:6d} ({pct:5.1f}%) {bar}")

    # 2. 应用层协议
    print("\n【应用层协议】")
    print("-" * 40)
    apps = [
        ('HTTP', stats['http']),
        ('HTTPS', stats['https']),
        ('DNS', stats['dns']),
        ('SSH', stats['ssh']),
        ('FTP', stats['ftp']),
        ('SMTP', stats['smtp']),
    ]
    for name, count in apps:
        if count > 0:
            pct = count / total * 100 if total else 0
            print(f"  {name:8s} {count:6d} ({pct:.1f}%)")

    # 3. 数据包大小
    if packet_sizes:
        print("\n【数据包大小】")
        print("-" * 40)
        print(f"  最小: {min(packet_sizes)} bytes")
        print(f"  最大: {max(packet_sizes)} bytes")
        print(f"  平均: {sum(packet_sizes)/len(packet_sizes):.1f} bytes")
        print(f"  总计: {sum(packet_sizes)/1024:.2f} KB")

    # 4. 时间范围
    if timestamps:
        print("\n【时间信息】")
        print("-" * 40)
        duration = max(timestamps) - min(timestamps)
        print(f"  起始: {datetime.fromtimestamp(min(timestamps)).strftime('%H:%M:%S')}")
        print(f"  结束: {datetime.fromtimestamp(max(timestamps)).strftime('%H:%M:%S')}")
        print(f"  时长: {duration:.2f} 秒")
        print(f"  速率: {total/duration:.1f} 包/秒" if duration > 0 else "  速率: N/A")

    # 5. Top IP
    if src_ips:
        print("\n【Top 10 源 IP】")
        print("-" * 40)
        for ip, count in src_ips.most_common(10):
            print(f"  {ip:20s} {count:6d} 包")

    if dst_ips:
        print("\n【Top 10 目的 IP】")
        print("-" * 40)
        for ip, count in dst_ips.most_common(10):
            print(f"  {ip:20s} {count:6d} 包")

    # 6. Top 端口
    if dst_ports:
        print("\n【Top 10 目的端口】")
        print("-" * 40)
        for port, count in dst_ports.most_common(10):
            service = get_service_name(port)
            print(f"  {port:6d} ({service:10s}) {count:6d} 包")

    # 7. 连接数
    print("\n【连接统计】")
    print("-" * 40)
    print(f"  独立连接数: {len(connections)}")

    print(f"\n{'='*60}")
    print("  分析完成")
    print(f"{'='*60}\n")

    return stats


def get_service_name(port):
    """根据端口返回服务名称"""
    services = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
    }
    return services.get(port, 'Unknown')


def analyze_for_api(pcap_path):
    """为后端 API 提供简化版分析结果"""
    try:
        from scapy.all import rdpcap, TCP, UDP, IP
    except ImportError:
        return {'error': 'scapy not installed'}

    if not os.path.exists(pcap_path):
        return {'error': 'file not found'}

    packets = rdpcap(pcap_path)
    total = len(packets)

    tcp_count = sum(1 for p in packets if p.haslayer(TCP))
    udp_count = sum(1 for p in packets if p.haslayer(UDP))
    http_count = sum(1 for p in packets if p.haslayer(TCP) and (p[TCP].dport == 80 or p[TCP].sport == 80))
    https_count = sum(1 for p in packets if p.haslayer(TCP) and (p[TCP].dport == 443 or p[TCP].sport == 443))
    dns_count = sum(1 for p in packets if p.haslayer(UDP) and (p[UDP].dport == 53 or p[UDP].sport == 53))

    return {
        'total_packets': total,
        'protocols': {
            'TCP': tcp_count,
            'UDP': udp_count,
            'HTTP': http_count,
            'HTTPS': https_count,
            'DNS': dns_count,
        },
        'file_size': os.path.getsize(pcap_path)
    }


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python pcap_analyzer.py <pcap文件路径>")
        print("示例: python pcap_analyzer.py test.pcap")
        sys.exit(1)

    analyze_pcap(sys.argv[1])
