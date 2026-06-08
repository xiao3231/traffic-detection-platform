# -*- coding: utf-8 -*-
"""实时/离线抓包会话管理（供 Web 协议分析页使用）"""

import os
import threading
import time
from datetime import datetime, timezone

from scapy.all import Ether, hexdump, raw, sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.interfaces import get_if_list

_BPF_PROTO_MAP = {
    'TCP': 'tcp',
    'UDP': 'udp',
    'ICMP': 'icmp',
    'IP': 'ip',
    'ARP': 'arp',
    'IPV6': 'ipv6',
}


def _normalize_bpf(expr):
    """tcpdump/BPF 协议名需小写，自动把 UDP、TCP 等转为 udp、tcp。"""
    expr = (expr or '').strip()
    if not expr:
        return ''
    return ' '.join(_BPF_PROTO_MAP.get(token, token) for token in expr.split())


def _validate_bpf(expr):
    if not expr:
        return
    try:
        from scapy.arch.common import compile_filter

        compile_filter(expr)
    except Exception as exc:
        raise ValueError(
            f'BPF 表达式无法识别：「{expr}」。'
            '协议名请用小写，例如 udp、tcp、icmp，或 tcp port 80'
        ) from exc


def _prepare_bpf(expr):
    normalized = _normalize_bpf(expr)
    _validate_bpf(normalized)
    return normalized


def _friendly_capture_error(exc):
    msg = str(exc)
    if 'Failed to compile filter expression' in msg:
        return (
            'BPF 过滤表达式写错了（不是“文件里没有这种包”）。'
            '协议名请用小写：udp、tcp、icmp，例如 tcp port 80。'
            f'原始错误：{msg}'
        )
    return msg


def _timestamp2time(ts):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(ts)))


def _summarize_packet(pkt, index):
    proto_names = ['TCP', 'UDP', 'ICMP', 'IPv6', 'IP', 'ARP', 'Ether']
    proto = 'Unknown'
    for pn in proto_names:
        if pn in pkt:
            proto = pn
            break

    if proto in ('ARP', 'Ether'):
        src = getattr(pkt, 'src', '') or ''
        dst = getattr(pkt, 'dst', '') or ''
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    elif IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    else:
        src = ''
        dst = ''

    return {
        'index': index,
        'time': _timestamp2time(pkt.time),
        'src': str(src),
        'dst': str(dst),
        'proto': proto,
        'length': len(pkt),
        'info': pkt.summary(),
    }


def _build_dissect_tree(pkt):
    lines = (pkt.show(dump=True)).split('\n')
    nodes = []
    stack = []
    for line in lines:
        if line.startswith('#'):
            text = line.strip('# ')
            node = {'text': text, 'children': []}
            if not stack:
                nodes.append(node)
            else:
                stack[-1]['children'].append(node)
            stack.append(node)
        elif line.strip():
            text = line.strip()
            if stack:
                stack[-1]['children'].append({'text': text, 'children': []})
    return nodes


def _checksum_results(pkt):
    results = {}
    try:
        rebuilt = Ether(raw(pkt))
    except Exception:
        return results

    if IP in pkt:
        results['ip'] = 'OK' if rebuilt[IP].chksum == pkt[IP].chksum else 'Error'
    if TCP in pkt:
        results['tcp'] = 'OK' if rebuilt[TCP].chksum == pkt[TCP].chksum else 'Error'
    elif UDP in pkt:
        results['udp'] = 'OK' if rebuilt[UDP].chksum == pkt[UDP].chksum else 'Error'
    elif ICMP in pkt:
        results['icmp'] = 'OK' if rebuilt[ICMP].chksum == pkt[ICMP].chksum else 'Error'
    return results


class CaptureService:
    MAX_PACKETS = 5000

    def __init__(self):
        self._lock = threading.Lock()
        self._packets = []
        self._pending = []
        self._running = False
        self._paused = False
        self._stop_event = threading.Event()
        self._thread = None
        self._bpf = ''
        self._mode = 'idle'
        self._session_meta = {}
        self._offline_path = None

    def status(self):
        with self._lock:
            return {
                'running': self._running,
                'paused': self._paused,
                'mode': self._mode,
                'packet_count': len(self._packets),
                'bpf_filter': self._bpf,
                'session': dict(self._session_meta),
                'last_error': self._session_meta.get('error'),
                'has_offline_source': bool(
                    self._offline_path and os.path.isfile(self._offline_path)
                ),
                'offline_source': (
                    os.path.basename(self._offline_path)
                    if self._offline_path
                    else None
                ),
            }

    def list_interfaces(self):
        try:
            return get_if_list()
        except Exception:
            return []

    def _consume(self, pkt):
        with self._lock:
            if self._paused:
                return
            if len(self._packets) >= self.MAX_PACKETS:
                return
            self._packets.append(pkt)
            summary = _summarize_packet(pkt, len(self._packets))
            self._pending.append(summary)

    def drain_pending(self):
        with self._lock:
            out = list(self._pending)
            self._pending.clear()
            return out

    def list_summaries(self):
        """返回缓冲区中全部包的摘要（供离线解析结束后一次性同步列表）。"""
        with self._lock:
            return [_summarize_packet(pkt, i + 1) for i, pkt in enumerate(self._packets)]

    def _sniff_loop(self, offline=None):
        try:
            sniff(
                prn=self._consume,
                stop_filter=lambda _: self._stop_event.is_set(),
                filter=self._bpf or None,
                iface=None,
                offline=offline,
                store=False,
            )
        except Exception as exc:
            with self._lock:
                self._session_meta['error'] = _friendly_capture_error(exc)
        finally:
            with self._lock:
                self._running = False
                self._mode = 'idle'

    def start_live(self, bpf_filter=''):
        self._reset_buffer()
        self._offline_path = None
        self._bpf = _prepare_bpf(bpf_filter)
        self._stop_event.clear()
        self._paused = False
        self._running = True
        self._mode = 'live'
        self._session_meta = {
            'started_at': datetime.now(timezone.utc),
            'bpf_filter': self._bpf,
            'session_mode': 'live',
        }
        self._thread = threading.Thread(target=self._sniff_loop, kwargs={'offline': None}, daemon=True)
        self._thread.start()

    def load_offline(self, pcap_path, bpf_filter='', opened_at=None):
        path = os.path.abspath(pcap_path)
        if not os.path.isfile(path):
            raise FileNotFoundError(f'pcap 文件不存在: {path}')
        with self._lock:
            keep_opened = None
            if self._offline_path and os.path.abspath(self._offline_path) == path:
                keep_opened = self._session_meta.get('opened_at')
        opened = opened_at or keep_opened or datetime.now(timezone.utc)
        self._reset_buffer()
        self._offline_path = path
        self._bpf = _prepare_bpf(bpf_filter)
        self._stop_event.clear()
        self._paused = False
        self._running = True
        self._mode = 'offline'
        self._session_meta = {
            'started_at': opened,
            'opened_at': opened,
            'bpf_filter': self._bpf,
            'source_file': os.path.basename(path),
            'session_mode': 'offline',
        }
        self._thread = threading.Thread(target=self._sniff_loop, kwargs={'offline': path}, daemon=True)
        self._thread.start()

    def apply_bpf(self, bpf_filter=''):
        """对已打开的离线 pcap 按 BPF 重新解析（需先完成打开或上一次过滤）。"""
        if self._running:
            raise RuntimeError('请先停止当前任务')
        if not self._offline_path or not os.path.isfile(self._offline_path):
            raise RuntimeError('请先使用「打开 pcap」加载文件后再应用过滤器')
        self.load_offline(self._offline_path, bpf_filter=bpf_filter)

    def cancel_bpf(self):
        """清除 BPF 并重新加载当前离线 pcap（显示全部包）。"""
        self.apply_bpf('')

    def pause(self):
        with self._lock:
            self._paused = True

    def resume(self):
        with self._lock:
            self._paused = False

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _reset_buffer(self):
        with self._lock:
            self._packets.clear()
            self._pending.clear()
            self._session_meta = {}

    def clear(self):
        self.stop()
        self._reset_buffer()
        self._offline_path = None
        self._mode = 'idle'

    def get_packet_detail(self, index):
        with self._lock:
            if index < 1 or index > len(self._packets):
                return None
            pkt = self._packets[index - 1]
        return {
            'index': index,
            'summary': _summarize_packet(pkt, index),
            'tree': _build_dissect_tree(pkt),
            'hexdump': hexdump(pkt, dump=True),
            'checksums': _checksum_results(pkt),
        }

    def save_pcap(self, folder, filename):
        with self._lock:
            packets = list(self._packets)
        if not packets:
            return None
        path = os.path.join(folder, filename)
        wrpcap(path, packets)
        return path

    def dump_buffer_to_path(self, path):
        """将当前内存中的包写入 pcap（用于特征预览等）。"""
        with self._lock:
            if not self._packets:
                return False
            wrpcap(path, list(self._packets))
        return True

    def snapshot_for_db(self):
        with self._lock:
            meta = dict(self._session_meta)
            # 有离线上传路径或原始文件名 → 离线；否则为网卡实时抓包
            is_upload = bool(self._offline_path) or bool(meta.get('source_file'))
            return {
                'packet_count': len(self._packets),
                'bpf_filter': self._bpf,
                'mode': self._mode,
                'meta': meta,
                'capture_origin': 'offline' if is_upload else 'live',
            }


capture_service = CaptureService()
