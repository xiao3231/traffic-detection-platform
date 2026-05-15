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
                self._session_meta['error'] = str(exc)
        finally:
            with self._lock:
                self._running = False
                self._mode = 'idle'

    def start_live(self, bpf_filter=''):
        self._reset_buffer()
        self._bpf = bpf_filter or ''
        self._stop_event.clear()
        self._paused = False
        self._running = True
        self._mode = 'live'
        self._session_meta = {
            'started_at': datetime.now(timezone.utc),
            'bpf_filter': self._bpf,
        }
        self._thread = threading.Thread(target=self._sniff_loop, kwargs={'offline': None}, daemon=True)
        self._thread.start()

    def load_offline(self, pcap_path, bpf_filter=''):
        self._reset_buffer()
        self._bpf = bpf_filter or ''
        self._stop_event.clear()
        self._paused = False
        self._running = True
        self._mode = 'offline'
        self._session_meta = {
            'started_at': datetime.now(timezone.utc),
            'bpf_filter': self._bpf,
            'source_file': os.path.basename(pcap_path),
        }
        self._thread = threading.Thread(target=self._sniff_loop, kwargs={'offline': pcap_path}, daemon=True)
        self._thread.start()

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
            return {
                'packet_count': len(self._packets),
                'bpf_filter': self._bpf,
                'mode': self._mode,
                'meta': dict(self._session_meta),
            }


capture_service = CaptureService()
