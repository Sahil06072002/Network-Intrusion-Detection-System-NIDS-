import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import time
import os
import numpy as np
import threading
from collections import deque

class TrafficCapture:
    def __init__(self, interface=None, output_file="traffic_capture.csv", timeout=60):
        self.interface = interface
        self.output_file = output_file
        self.timeout = timeout
        self.flows = {} # (src_ip, dst_ip, src_port, dst_port, proto) -> Flow object
        self.finished_flows = []
        self.columns = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
            'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
            'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean',
            'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'
        ]

    def packet_callback(self, packet):
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
            flags = packet[TCP].flags
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flags = 0
        else:
            return

        # Create flow key (bidirectional)
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        
        if key not in self.flows:
            self.flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, proto)
        
        self.flows[key].add_packet(packet, src_ip)

    def start_capture(self, duration=None):
        print(f"Starting capture on {self.interface or 'default interface'}...")
        scapy.sniff(iface=self.interface, prn=self.packet_callback, timeout=duration or self.timeout, store=0)
        print("Capture finished. Processing flows...")
        self.export_to_csv()

    def export_to_csv(self):
        data = []
        for flow in self.flows.values():
            data.append(flow.get_features())
        
        df = pd.DataFrame(data, columns=self.columns)
        df.to_csv(self.output_file, index=False)
        print(f"Flows exported to {self.output_file}")

class Flow:
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
        ip = packet[IP]
        
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

        # Global Flags (Simplified)
        if packet.haslayer(TCP):
            f = packet[TCP].flags
            if 'F' in f: self.fin_cnt += 1
            if 'S' in f: self.syn_cnt += 1
            if 'R' in f: self.rst_cnt += 1
            if 'P' in f: self.psh_cnt += 1
            if 'A' in f: self.ack_cnt += 1
            if 'U' in f: self.urg_cnt += 1
            # CWE/ECE are less common in standard Scapy flags but can be checked
            if packet[TCP].reserved & 0x01: self.cwe_cnt += 1
            if packet[TCP].reserved & 0x02: self.ece_cnt += 1

        self.last_seen = timestamp

    def get_features(self):
        duration = (self.last_seen - self.start_time) * 1e6
        fwd_sum = sum(self.fwd_lengths)
        bwd_sum = sum(self.bwd_lengths)
        all_lengths = self.fwd_lengths + self.bwd_lengths
        
        # Helper to get stats
        def get_stats(arr):
            if not arr: return 0, 0, 0, 0
            return max(arr), min(arr), np.mean(arr), np.std(arr)

        f_max, f_min, f_mean, f_std = get_stats(self.fwd_lengths)
        b_max, b_min, b_mean, b_std = get_stats(self.bwd_lengths)
        all_max, all_min, all_mean, all_std = get_stats(all_lengths)
        
        f_iat_max, f_iat_min, f_iat_mean, f_iat_std = get_stats(self.fwd_iat)
        b_iat_max, b_iat_min, b_iat_mean, b_iat_std = get_stats(self.bwd_iat)
        
        flow_iat = []
        if len(all_lengths) > 1:
            # Reconstruct flow IAT from start_time? No, easier to just track all timestamps
            # For simplicity, we'll use fwd_iat and bwd_iat combined if needed, 
            # or just return 0 for now as it's complex to track perfectly without full packet list
            flow_iat = self.fwd_iat + self.bwd_iat # Approximation
        
        flow_iat_max, flow_iat_min, flow_iat_mean, flow_iat_std = get_stats(flow_iat)

        return [
            self.dst_port, duration, self.fwd_packets, self.bwd_packets,
            fwd_sum, bwd_sum, f_max, f_min, f_mean, f_std,
            b_max, b_min, b_mean, b_std,
            (fwd_sum + bwd_sum) / (duration / 1e6) if duration > 0 else 0,
            (self.fwd_packets + self.bwd_packets) / (duration / 1e6) if duration > 0 else 0,
            flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
            sum(self.fwd_iat), f_iat_mean, f_iat_std, f_iat_max, f_iat_min,
            sum(self.bwd_iat), b_iat_mean, b_iat_std, b_iat_max, b_iat_min,
            self.fwd_psh_flags, self.bwd_psh_flags, self.fwd_urg_flags, self.bwd_urg_flags,
            self.fwd_header_len, self.bwd_header_len,
            self.fwd_packets / (duration / 1e6) if duration > 0 else 0,
            self.bwd_packets / (duration / 1e6) if duration > 0 else 0,
            all_min, all_max, all_mean, all_std, np.var(all_lengths) if all_lengths else 0,
            self.fin_cnt, self.syn_cnt, self.rst_cnt, self.psh_cnt, self.ack_cnt, self.urg_cnt,
            self.cwe_cnt, self.ece_cnt,
            self.bwd_packets / self.fwd_packets if self.fwd_packets > 0 else 0,
            all_mean, # Average Packet Size
            f_mean, # Avg Fwd Segment Size
            b_mean, # Avg Bwd Segment Size
            self.fwd_header_len, # Fwd Header Length.1
            0, 0, 0, 0, 0, 0, # Avg Bulk placeholders
            self.fwd_packets, fwd_sum, self.bwd_packets, bwd_sum, # Subflow stats
            self.init_win_fwd, self.init_win_bwd, self.act_data_pkt_fwd, self.min_seg_size_fwd,
            0, 0, 0, 0, # Active stats placeholders
            0, 0, 0, 0, # Idle stats placeholders
            "BENIGN" # Placeholder Label
        ]

if __name__ == "__main__":
    capture = TrafficCapture(output_file="all_traffic.csv", timeout=300)
    capture.start_capture()
