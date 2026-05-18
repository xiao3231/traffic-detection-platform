# -*- coding: utf-8 -*-
"""流级特征名称及网安含义说明（训练 / 检测 / 协议分析预览共用）。"""

PROTOCOL_LIST = ['IP', 'UDP', 'DNS ANS', 'DNS Qry', 'IPV6', 'ICMPv6', 'TLS']

BASE_FEATURE_NAMES = [
    'len_mean',
    'len_std',
    'time_mean',
    'time_std',
    'num_unknown',
    *PROTOCOL_LIST,
]

EXTRA_FEATURE_NAMES = [
    'packet_count',
    'small_pkt_ratio',
    'iat_max',
    'byte_total',
    'distinct_ports',
]

FEATURE_NAMES = BASE_FEATURE_NAMES + EXTRA_FEATURE_NAMES

# 标签：1=安全(normal)，0=恶意(malicious)
LABEL_SAFE = 1
LABEL_MALICIOUS = 0

FEATURE_SECURITY_DOC = {
    'len_mean': '流内 IP 包长度均值；异常偏大/偏小可能对应隧道、分片或畸形流量。',
    'len_std': '包长波动；扫描、交互式 shell 等常表现为高方差。',
    'time_mean': '包间隔时间均值（秒）；心跳 C2、慢速渗透可能间隔稳定。',
    'time_std': '包间隔方差；突发扫描或 DDoS 常间隔分布异常。',
    'num_unknown': '无法解析源/目的端口的包占比；协议识别失败或非标流量。',
    'IP': 'IPv4 相关报文计数；基础连通与扫描活动指标。',
    'UDP': 'UDP 报文计数；DNS 隧道、放大攻击等常依赖 UDP。',
    'DNS ANS': 'DNS 应答次数；异常应答量可能关联 DGA、恶意域名解析。',
    'DNS Qry': 'DNS 查询次数；高频查询可能为域名生成或数据渗出。',
    'IPV6': 'IPv6 报文计数；双栈环境与部分恶意工具流量。',
    'ICMPv6': 'ICMPv6 报文计数；异常可关联探测或隧道尝试。',
    'TLS': 'TLS/加密会话相关计数；HTTPS C2 等（依赖解析深度）。',
    'packet_count': '该流包含的包总数；端口扫描、洪水常单流包数异常偏高。',
    'small_pkt_ratio': '小于 64 字节的包占比；SYN 扫描、ACK 探测等小包行为。',
    'iat_max': '流内最大包间隔（秒）；长时间静默后突发可能可疑。',
    'byte_total': '流内总字节数；数据渗出、大文件传输线索。',
    'distinct_ports': '流内不同端口对数量；横向扫描、多端口探测时升高。',
}


def feature_schema_payload():
    """供 API 返回的 JSON 结构。"""
    return {
        'feature_names': FEATURE_NAMES,
        'protocol_list': PROTOCOL_LIST,
        'descriptions': FEATURE_SECURITY_DOC,
        'label_safe': LABEL_SAFE,
        'label_malicious': LABEL_MALICIOUS,
    }


def default_feature_vector():
    return [0.0] * len(FEATURE_NAMES)


def security_extra_features(sizes, time_list, ports):
    """从单条流的包长、时间戳序列、端口对列表计算网安扩展特征（5 维）。"""
    sizes = list(sizes or [])
    time_list = list(time_list or [])
    ports = list(ports or [])
    n = len(sizes)
    if n == 0:
        return [0.0] * len(EXTRA_FEATURE_NAMES)
    small_pkt_ratio = sum(1 for s in sizes if float(s) < 64) / n
    iat_max = float(max(time_list)) if len(time_list) > 1 else 0.0
    byte_total = float(sum(sizes))
    distinct_ports = len({tuple(p) for p in ports if p != ['UnKnow', 'UnKnow']})
    return [float(n), small_pkt_ratio, iat_max, byte_total, float(distinct_ports)]
