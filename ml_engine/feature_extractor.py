import time
import pandas as pd
import numpy as np
from scapy.layers.inet import IP, TCP, UDP

class Flow:
    """Expert-level Flow representation for extracting 79 network features."""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.start_time = time.time()
        self.last_seen = self.start_time
        
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_lengths = []
        self.bwd_lengths = []
        self.fwd_iat = []
        self.bwd_iat = []
        self.fwd_last_timestamp = None
        self.bwd_last_timestamp = None
        
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        
        self.fin_cnt = 0
        self.syn_cnt = 0
        self.rst_cnt = 0
        self.psh_cnt = 0
        self.ack_cnt = 0
        self.urg_cnt = 0
        self.cwe_cnt = 0
        self.ece_cnt = 0
        
        self.init_win_fwd = 0
        self.init_win_bwd = 0
        self.act_data_pkt_fwd = 0
        self.min_seg_size_fwd = 0

    def add_packet(self, packet, direction_ip):
        timestamp = time.time()
        pkt_len = len(packet)
        
        is_fwd = (direction_ip == self.src_ip)
        
        if is_fwd:
            self.fwd_packets += 1
            self.fwd_lengths.append(pkt_len)
            if self.fwd_last_timestamp:
                self.fwd_iat.append((timestamp - self.fwd_last_timestamp) * 1e6)
            self.fwd_last_timestamp = timestamp
            
            if packet.haslayer(TCP):
                if self.fwd_packets == 1:
                    self.init_win_fwd = packet[TCP].window
                if 'P' in packet[TCP].flags: self.fwd_psh_flags += 1
                if 'U' in packet[TCP].flags: self.fwd_urg_flags += 1
                self.fwd_header_len += len(packet[TCP])
                if len(packet[TCP].payload) > 0: self.act_data_pkt_fwd += 1
                self.min_seg_size_fwd = min(self.min_seg_size_fwd or 65535, len(packet[TCP]))
        else:
            self.bwd_packets += 1
            self.bwd_lengths.append(pkt_len)
            if self.bwd_last_timestamp:
                self.bwd_iat.append((timestamp - self.bwd_last_timestamp) * 1e6)
            self.bwd_last_timestamp = timestamp
            
            if packet.haslayer(TCP):
                if self.bwd_packets == 1:
                    self.init_win_bwd = packet[TCP].window
                if 'P' in packet[TCP].flags: self.bwd_psh_flags += 1
                if 'U' in packet[TCP].flags: self.bwd_urg_flags += 1
                self.bwd_header_len += len(packet[TCP])

        if packet.haslayer(TCP):
            f = packet[TCP].flags
            if 'F' in f: self.fin_cnt += 1
            if 'S' in f: self.syn_cnt += 1
            if 'R' in f: self.rst_cnt += 1
            if 'P' in f: self.psh_cnt += 1
            if 'A' in f: self.ack_cnt += 1
            if 'U' in f: self.urg_cnt += 1
            if packet[TCP].reserved & 0x01: self.cwe_cnt += 1
            if packet[TCP].reserved & 0x02: self.ece_cnt += 1

        self.last_seen = timestamp

    def get_feature_dict(self):
        duration = (self.last_seen - self.start_time) * 1e6
        fwd_sum = sum(self.fwd_lengths)
        bwd_sum = sum(self.bwd_lengths)
        all_lengths = self.fwd_lengths + self.bwd_lengths
        
        def get_stats(arr):
            if not arr: return 0, 0, 0, 0
            return max(arr), min(arr), np.mean(arr), np.std(arr)

        f_max, f_min, f_mean, f_std = get_stats(self.fwd_lengths)
        b_max, b_min, b_mean, b_std = get_stats(self.bwd_lengths)
        all_max, all_min, all_mean, all_std = get_stats(all_lengths)
        
        f_iat_max, f_iat_min, f_iat_mean, f_iat_std = get_stats(self.fwd_iat)
        b_iat_max, b_iat_min, b_iat_mean, b_iat_std = get_stats(self.bwd_iat)
        flow_iat = self.fwd_iat + self.bwd_iat
        flow_iat_max, flow_iat_min, flow_iat_mean, flow_iat_std = get_stats(flow_iat)

        dur_sec = duration / 1e6 if duration > 0 else 1 # Avoid div by zero
        
        return {
            'Destination Port': self.dst_port,
            'Flow Duration': duration,
            'Total Fwd Packets': self.fwd_packets,
            'Total Backward Packets': self.bwd_packets,
            'Total Length of Fwd Packets': fwd_sum,
            'Total Length of Bwd Packets': bwd_sum,
            'Fwd Packet Length Max': f_max,
            'Fwd Packet Length Min': f_min,
            'Fwd Packet Length Mean': f_mean,
            'Fwd Packet Length Std': f_std,
            'Bwd Packet Length Max': b_max,
            'Bwd Packet Length Min': b_min,
            'Bwd Packet Length Mean': b_mean,
            'Bwd Packet Length Std': b_std,
            'Flow Bytes/s': (fwd_sum + bwd_sum) / dur_sec,
            'Flow Packets/s': (self.fwd_packets + self.bwd_packets) / dur_sec,
            'Flow IAT Mean': flow_iat_mean,
            'Flow IAT Std': flow_iat_std,
            'Flow IAT Max': flow_iat_max,
            'Flow IAT Min': flow_iat_min,
            'Fwd IAT Total': sum(self.fwd_iat),
            'Fwd IAT Mean': f_iat_mean,
            'Fwd IAT Std': f_iat_std,
            'Fwd IAT Max': f_iat_max,
            'Fwd IAT Min': f_iat_min,
            'Bwd IAT Total': sum(self.bwd_iat),
            'Bwd IAT Mean': b_iat_mean,
            'Bwd IAT Std': b_iat_std,
            'Bwd IAT Max': b_iat_max,
            'Bwd IAT Min': b_iat_min,
            'Fwd PSH Flags': self.fwd_psh_flags,
            'Bwd PSH Flags': self.bwd_psh_flags,
            'Fwd URG Flags': self.fwd_urg_flags,
            'Bwd URG Flags': self.bwd_urg_flags,
            'Fwd Header Length': self.fwd_header_len,
            'Bwd Header Length': self.bwd_header_len,
            'Fwd Packets/s': self.fwd_packets / dur_sec,
            'Bwd Packets/s': self.bwd_packets / dur_sec,
            'Min Packet Length': all_min,
            'Max Packet Length': all_max,
            'Packet Length Mean': all_mean,
            'Packet Length Std': all_std,
            'Packet Length Variance': np.var(all_lengths) if all_lengths else 0,
            'FIN Flag Count': self.fin_cnt,
            'SYN Flag Count': self.syn_cnt,
            'RST Flag Count': self.rst_cnt,
            'PSH Flag Count': self.psh_cnt,
            'ACK Flag Count': self.ack_cnt,
            'URG Flag Count': self.urg_cnt,
            'CWE Flag Count': self.cwe_cnt,
            'ECE Flag Count': self.ece_cnt,
            'Down/Up Ratio': self.bwd_packets / self.fwd_packets if self.fwd_packets > 0 else 0,
            'Average Packet Size': all_mean,
            'Avg Fwd Segment Size': f_mean,
            'Avg Bwd Segment Size': b_mean,
            'Fwd Header Length.1': self.fwd_header_len,
            'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': self.fwd_packets, 'Subflow Fwd Bytes': fwd_sum,
            'Subflow Bwd Packets': self.bwd_packets, 'Subflow Bwd Bytes': bwd_sum,
            'Init_Win_bytes_forward': self.init_win_fwd,
            'Init_Win_bytes_backward': self.init_win_bwd,
            'act_data_pkt_fwd': self.act_data_pkt_fwd,
            'min_seg_size_forward': self.min_seg_size_fwd,
            'Active Mean': 0, 'Active Std': 0, 'Active Max': 0, 'Active Min': 0,
            'Idle Mean': 0, 'Idle Std': 0, 'Idle Max': 0, 'Idle Min': 0,
            'Protocol': self.proto,
            'Source IP': self.src_ip,
            'Destination IP': self.dst_ip
        }

class FlowAggregator:
    """Expert-level Flow Aggregator for real-time network monitoring."""
    def __init__(self, timeout=5.0):
        self.active_flows = {} # (src_ip, dst_ip, src_port, dst_port, proto) -> Flow
        self.finished_flows = []
        self.timeout = timeout

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        proto = ip.proto
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = 0
        dst_port = 0
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            return

        # key (bidirectional)
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        
        if key not in self.active_flows:
            self.active_flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, proto)
        
        self.active_flows[key].add_packet(packet, src_ip)
        self.check_timeouts(time.time())

    def check_timeouts(self, current_time):
        keys_to_remove = []
        for key, flow in self.active_flows.items():
            if current_time - flow.last_seen > self.timeout:
                self.finished_flows.append(flow)
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.active_flows[key]

    def get_finished_flows(self):
        flows = self.finished_flows
        self.finished_flows = []
        return flows

    def to_dataframe(self, flows):
        if not flows:
            return pd.DataFrame()
        return pd.DataFrame([f.get_feature_dict() for f in flows])
