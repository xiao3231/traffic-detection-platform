#!/usr/bin/env python
# -*- coding:utf-8 -*-
import numpy as np
from datetime import datetime


# # 加载文件
# def LoadFile():
#     badXss='./badx.csv'
#     goodXss='./goodx.csv'
#     bf=[x.strip().lower() for x in open(badXss,'r').readlines()]
#     gf=[x.strip().lower() for x in open(goodXss,'r').readlines()]
#     return bf,gf

# dict={(source_ip,dest_ip):[[len1,len2,len3...][start_time,time1,time2,...],[IPv6/IP, 'TCP'/'UDP',DNS Qry/Ans],[source_port,dest_port]],...}
# 还可以统计ARP地址解析协议的出现频率
# 现在根据情况，首先实现长度和时间
class GetFeature():
    def __init__(self):
        pass

    def MakeFeatures(self,file_name):
        dict = {}
        feature=[]
        protocol_list=['IP','UDP','DNS ANS','DNS Qry','IPV6','ICMPv6','TLS']
        
        # 检测文件类型：如果是pcap文件，先转换为csv
        if file_name.endswith('.pcap'):
            return self._make_features_from_pcap(file_name)
        
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f.readlines():
                x=line[:-1].split(',')

                if x[3].isdigit():
                    x[3]=int(x[3])
                else:
                    x[3]=int(x[4])
                flag=3
                if x[1]=="" or x[2]=="":

                    continue
                if(((x[1],x[2]) not in dict)&((x[2],x[1]) not in dict)):
                    # 初始化一个对话数据历史
                    dict[(x[1], x[2])]=[]
                    dict[(x[1],x[2])].append([x[3]])
                    dict[(x[1],x[2])].append([x[0]])
                    dict[(x[1], x[2])].append({}) #存放协议
                    dict[(x[1], x[2])].append([]) #存放用到的端口

                    for item in protocol_list:
                        dict[(x[1], x[2])][2][item]=0
                    flag=0
                elif ((x[1],x[2]) in dict):
                    flag=1
                    dict[(x[1], x[2])][0].append(x[3])
                    dict[(x[1], x[2])][1].append(x[0])
                elif ((x[2],x[1]) in dict):
                    flag=2
                    dict[(x[2], x[1])][0].append(x[3])
                    dict[(x[2], x[1])][1].append(x[0])
                if flag==1:
                    for item in protocol_list:
                        if (item in x[4])or(item in x[5]):
                            dict[(x[1], x[2])][2][item] +=1
                elif flag==2:
                    for item in protocol_list:
                        if (item in x[4])or(item in x[5]):
                            dict[(x[2], x[1])][2][item] +=1
                elif flag!=0:
                    print('异常数据: {}'.format(line))
                    continue


                if x[-1]=='bad':
                    source_port=x[-3]
                    dest_port=x[-2]
                else:
                    source_port=x[-4]
                    dest_port=x[-3]

                if flag==1:
                    dict[(x[1], x[2])][3].append([source_port, dest_port])
                elif flag==2:
                    dict[(x[2], x[1])][3].append([source_port, dest_port])

# 处理特征 feature=[[len_mean,len_std,time_mean,time_std,frequence of'IP','UDP','DNS ANS','DNS Qry','IPV6',len_APR_mean,len_APR_std]]

        for key in dict:
            time_list=[]
            current_list=[]
            len_mean=np.mean(dict[key][0])
            len_std=np.std(dict[key][0])
            for i,item in enumerate(dict[key][1]):
                # 清理时间字符串（去除前缀如 'x'）
                clean_item = item.lstrip('x').strip()
                try:
                    if i==0:
                        time_s=datetime.strptime(clean_item,"%Y-%m-%d %H:%M:%S")
                        time_list.append(0)
                    else:
                        time_c=datetime.strptime(clean_item,"%Y-%m-%d %H:%M:%S")
                        time_list.append((time_c-time_s).seconds)
                except ValueError:
                    # 如果时间格式错误，使用索引作为时间差
                    time_list.append(i)
            # time_list=[0,3,4,7,9,...]
            time_mean=np.mean(time_list)
            time_std=np.var(time_list)
            # 记录空端口的数量（修复：检查列表是否为['UnKnow', 'UnKnow']）
            num_unkown=0
            for item in dict[key][3]:
                if item == ['UnKnow', 'UnKnow']:
                    num_unkown+=1

            current_list=[len_mean,len_std,time_mean,time_std,num_unkown]
            for item in protocol_list:
                current_list.append(dict[key][2][item])
            feature.append(current_list)
        return feature

    def _make_features_from_pcap(self, pcap_path):
        """从pcap文件直接提取特征（用于在线检测）- 与CSV特征提取保持一致"""
        from scapy.all import rdpcap
        from collections import defaultdict
        import numpy as np
        from datetime import datetime
        import time as time_module
        
        packets = rdpcap(pcap_path)
        
        # 按连接分组（与CSV一致：无序的IP对）
        flows = defaultdict(lambda: {'sizes': [], 'times': [], 'protocols': defaultdict(int), 'ports': []})
        
        start_time = None
        
        for pkt in packets:
            if start_time is None:
                # 处理 scapy 的 Decimal 时间戳
                try:
                    start_time = datetime.fromtimestamp(float(pkt.time))
                except (ValueError, TypeError):
                    start_time = datetime.now()
            
            try:
                pkt_datetime = datetime.fromtimestamp(float(pkt.time))
            except (ValueError, TypeError):
                pkt_datetime = datetime.now()
            pkt_time_str = pkt_datetime.strftime("%Y-%m-%d %H:%M:%S")
            
            # 提取协议类型和端口信息（与PcapDecode.ether_decode一致）
            protocol = ''
            src_ip = ''
            dst_ip = ''
            src_port = 'UnKnow'
            dst_port = 'UnKnow'
            pkt_len = len(pkt)
            
            if pkt.haslayer("IP"):
                ip = pkt["IP"]
                src_ip = ip.src
                dst_ip = ip.dst
                
                if pkt.haslayer("TCP"):
                    tcp = pkt["TCP"]
                    src_port = str(tcp.sport)
                    dst_port = str(tcp.dport)
                    # 尝试获取协议名称
                    port_dict = {80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP'}
                    protocol = port_dict.get(tcp.dport, port_dict.get(tcp.sport, 'TCP'))
                elif pkt.haslayer("UDP"):
                    udp = pkt["UDP"]
                    src_port = str(udp.sport)
                    dst_port = str(udp.dport)
                    port_dict = {53: 'DNS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP'}
                    protocol = port_dict.get(udp.dport, port_dict.get(udp.sport, 'UDP'))
                else:
                    # 非TCP/UDP的IP协议
                    ip_proto_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
                    protocol = ip_proto_dict.get(ip.proto, f'IP-{ip.proto}')
                    src_port = 'UnKnow'
                    dst_port = 'UnKnow'
            elif pkt.haslayer("IPv6"):
                ipv6 = pkt["IPv6"]
                src_ip = ipv6.src
                dst_ip = ipv6.dst
                
                if pkt.haslayer("TCP"):
                    tcp = pkt["TCP"]
                    src_port = str(tcp.sport)
                    dst_port = str(tcp.dport)
                    protocol = 'TCP'
                elif pkt.haslayer("UDP"):
                    udp = pkt["UDP"]
                    src_port = str(udp.sport)
                    dst_port = str(udp.dport)
                    port_dict = {53: 'DNS', 546: 'DHCPv6-Client', 547: 'DHCPv6-Server'}
                    protocol = port_dict.get(udp.dport, port_dict.get(udp.sport, 'UDP'))
                else:
                    # IPv6扩展头
                    ip_proto_dict = {0: 'HOPOPT', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
                    nh = getattr(ipv6, 'nh', 58)
                    protocol = ip_proto_dict.get(nh, f'IPv6-{nh}')
                    src_port = 'UnKnow'
                    dst_port = 'UnKnow'
            else:
                # 非IP层（如ARP、Ether）
                src_ip = pkt.src
                dst_ip = pkt.dst
                if hasattr(pkt, 'type'):
                    ether_type_dict = {0x0806: 'ARP', 0x0800: 'IP', 0x86DD: 'IPv6', 0x8100: 'VLAN'}
                    protocol = ether_type_dict.get(pkt.type, f'Ether-{hex(pkt.type)}')
                else:
                    protocol = 'Unknown'
                src_port = 'UnKnow'
                dst_port = 'UnKnow'
            
            # 确定连接键（无序，与CSV一致）
            if src_ip and dst_ip:
                conn_key = tuple(sorted([src_ip, dst_ip]))
            else:
                # 使用 MAC 地址作为备用
                conn_key = tuple(sorted([pkt.src, pkt.dst]))
            
            flows[conn_key]['sizes'].append(pkt_len)
            flows[conn_key]['times'].append(pkt_time_str)
            
            # 协议统计（与CSV的protocol_list一致）
            # CSV检查info字段中是否包含协议名称，这里直接用解析出的protocol
            protocol_upper = protocol.upper()
            info_upper = pkt.summary().upper()
            
            # IP协议统计：包含'IP'但不是'ARP'
            if 'IP' in info_upper or ('IP' in protocol_upper and 'ARP' not in protocol_upper):
                if 'V6' in info_upper or 'IPV6' in protocol_upper:
                    flows[conn_key]['protocols']['IPV6'] += 1
                else:
                    flows[conn_key]['protocols']['IP'] += 1
            
            # 细分协议统计（检查info字段，与CSV一致）
            proto_list = ['UDP', 'DNS', 'IPV6', 'ICMPV6', 'TLS', 'ARP', 'HOPOPT']
            for proto in proto_list:
                if proto in info_upper:
                    proto_key = proto.replace(' ', '_').upper()
                    if proto_key == 'IPV6':
                        proto_key = 'IPV6'
                    elif proto_key == 'ICMPV6':
                        proto_key = 'ICMPv6'
                    elif proto_key == 'DNS':
                        # DNS分为查询和应答
                        if 'ANS' in info_upper or 'REPLY' in info_upper:
                            flows[conn_key]['protocols']['DNS ANS'] += 1
                        else:
                            flows[conn_key]['protocols']['DNS Qry'] += 1
                    elif proto_key == 'TLS':
                        flows[conn_key]['protocols']['TLS'] += 1
                    else:
                        if proto_key in flows[conn_key]['protocols']:
                            flows[conn_key]['protocols'][proto_key] += 1
            
            flows[conn_key]['ports'].append([src_port, dst_port])
        
        # 生成特征向量（与CSV的MakeFeatures一致）
        features = []
        protocol_list = ['IP', 'UDP', 'DNS ANS', 'DNS Qry', 'IPV6', 'ICMPv6', 'TLS']
        
        for conn_key, flow_data in flows.items():
            time_list = []
            first_time = None
            
            for i, time_str in enumerate(flow_data['times']):
                try:
                    clean_time = time_str.lstrip('x').strip()
                    t = datetime.strptime(clean_time, "%Y-%m-%d %H:%M:%S")
                    if first_time is None:
                        first_time = t
                        time_list.append(0)
                    else:
                        time_list.append((t - first_time).seconds)
                except ValueError:
                    time_list.append(i)
            
            sizes = flow_data['sizes']
            len_mean = np.mean(sizes) if sizes else 0
            len_std = np.std(sizes) if len(sizes) > 1 else 0
            time_mean = np.mean(time_list) if time_list else 0
            time_std = np.var(time_list) if len(time_list) > 1 else 0
            
            # 统计未知端口（与CSV特征提取保持一致：检查字符串'UnKnow'）
            num_unknown = 0
            for ports in flow_data['ports']:
                if ports == ['UnKnow', 'UnKnow']:
                    num_unknown += 1
            # 注：CSV特征提取实际bug导致num_unknown始终为0，为保持一致这里也设为0
            # 但为了后续改进，暂时保留正确的计算逻辑
            
            current_list = [len_mean, len_std, time_mean, time_std, num_unknown]
            for proto in protocol_list:
                current_list.append(flow_data['protocols'].get(proto, 0))
            
            features.append(current_list)
        
        # 如果没有提取到任何特征，返回一个默认特征向量
        if not features:
            features = [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]
        
        return features


if __name__=="__main__":
    filename='./goodx.csv'
    feature=GetFeature().MakeFeatures(filename)
    print(feature)




# def MakeFeatures(self,file_name):
#     # 定义一个空字典和一个空列表
#     dict = {}
#     feature=[]
#     # 定义协议类型列表
#     protocol_list=['IP','UDP','DNS ANS','DNS Qry','IPV6','ICMPv6','TLS']
#     # 打开文件
#     with open(file_name) as f:
#         # 逐行读取文件
#         for line in f.readlines():
#             # 将每行数据转换为列表
#             x=line[:-1].split(',')
#             # 判断数据包长度是否为数字，如果是则转换为整数类型，否则将另一个数据包长度转换为整数类型
#             if x[3].isdigit():
#                 x[3]=int(x[3])
#             else:
#                 x[3]=int(x[4])
#             # 标记变量，用于判断数据是否为新的对话数据
#             flag=3
#             # 如果源IP地址或目的IP地址为空，则跳过该行数据
#             if x[1]=="" or x[2]=="":
#                 continue
#             # 如果字典中不存在以源IP地址和目的IP地址为键的项，则初始化一个对话数据历史
#             if(((x[1],x[2]) not in dict)&((x[2],x[1]) not in dict)):
#                 # 初始化一个对话数据历史
#                 dict[(x[1], x[2])]=[]
#                 # 存储时间戳的列表
#                 dict[(x[1],x[2])].append([x[3]])
#                 # 存储协议类型的列表
#                 dict[(x[1],x[2])].append([x[0]])
#                 # 存储协议类型的字典
#                 dict[(x[1], x[2])].append({}) #存放协议
#                 # 存储用到的端口的列表
#                 dict[(x[1], x[2])].append([]) #存放用到的端口
#                 # 初始化协议类型字典
#                 for item in protocol_list:
#                     dict[(x[1], x[2])][2][item]=0
#                 # 将标记变量设置为0
#                 flag=0
#             # 如果字典中存在以源IP地址和目的IP地址为键的项，则将该行数据存储到对应的对话数据历史中
#             elif ((x[1],x[2]) in dict):
#                 # 将该行数据存储到对应的对话数据历史中
#                 dict[(x[1], x[2])][0].append(x[3])
#                 dict[(x[1], x[2])][1].append(x[0])
#                 # 将标记变量设置为1
#                 flag=1
#             elif ((x[2],x[1]) in dict):
#                 # 将该行数据存储到对应的对话数据历史中
#                 dict[(x[2], x[1])][0].append(x[3])
#                 dict[(x[2], x[1])][1].append(x[0])
#                 # 将标记变量设置为2
#                 flag=2
#             # 如果标记变量不为0、1或2，则输出异常数据并跳过该行数据
#             if flag!=0 and flag!=1 and flag!=2:
#                 print('异常数据: {}'.format(line))
#                 continue
#             # 统计协议类型的数量
#             for item in protocol_list:
#                 if (item in x[4])or(item in x[5]):
#                     if flag==1:
#                         dict[(x[1], x[2])][2][item] +=1
#                     elif flag==2:
#                         dict[(x[2], x[1])][2][item] +=1
#             # 统计用到的端口
#             if x[-1]=='bad':
#                 source_port=x[-3]
#                 dest_port=x[-2]
#             else:
#                 source_port=x[-4]
#                 dest_port=x[-3]
#             if flag==1:
#                 dict[(x[1], x[2])][3].append([source_port, dest_port])
#             elif flag==2:
#                 dict[(x[2], x[1])][3].append([source_port, dest_port])
#     # 遍历字典中的每一项，将其转换为特征向量
#     for key in dict:
#         # 定义一个空列表和一个空列表
#         time_list=[]
#         current_list=[]
#         # 计算数据包长度的平均值和标准差
#         len_mean=np.mean(dict[key][0])
#         len_std=np.std(dict[key][0])
#         # 遍历时间戳列表，计算时间戳之间的时间差
#         for i,item in enumerate(dict[key][1]):
#             if i==0:
#                 time_s=datetime.strptime(item,"%Y-%m-%d %H:%M:%S")
#                 time_list.append(0)
#             else:
#                 time_c=datetime.strptime(item,"%Y-%m-%d %H:%M:%S")
#                 time_list.append((time_c-time_s).seconds)
#         # 计算时间戳之间的平均时间差和方差
#         time_mean=np.mean(time_list)
#         time_std=np.var(time_list)
#         # 统计空端口的数量
#         num_unkown=0
#         for item in dict[key][3]:
#             if item=='UnKnow':
#                 num_unkown+=1
#         # 将特征存储到列表中
#         current_list=[len_mean,len_std,time_mean,time_std,num_unkown]
#         for item in protocol_list:
#             current_list.append(dict[key][2][item])
#         feature.append(current_list)
#     # 返回特征向量列表
#     return feature