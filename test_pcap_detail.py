import sys; sys.path.insert(0, '.')
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, IP
from collections import defaultdict

packets = rdpcap('traffic_platform/web_platform/upload/test8-malicious.pcap')
print(f'总包数: {len(packets)}')

ip_count = sum(1 for p in packets if p.haslayer(IP))
tcp_count = sum(1 for p in packets if p.haslayer(TCP))
udp_count = sum(1 for p in packets if p.haslayer(UDP))
arp_count = sum(1 for p in packets if not p.haslayer(IP))
print(f'IP: {ip_count}, TCP: {tcp_count}, UDP: {udp_count}, ARP/Other: {arp_count}')

flows = defaultdict(list)
for p in packets:
    if p.haslayer(IP):
        ip = p[IP]
        key = tuple(sorted([ip.src, ip.dst]))
        flows[key].append(p)

print(f'独立连接数: {len(flows)}')
for i, (key, pkts) in enumerate(list(flows.items())[:3]):
    print(f'连接{i}: {key[0]} <-> {key[1]}, 包数={len(pkts)}')
    sizes = [len(p) for p in pkts]
    print(f'  包大小: min={min(sizes)}, max={max(sizes)}, mean={sum(sizes)/len(sizes):.1f}')
