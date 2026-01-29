import pandas as pd
import numpy as np
import os

def generate_balanced_dataset(filename="all_4060.csv", entries=50, attack_ratio=0.4):
    """
    Expert System: Generates a high-fidelity balanced dataset with the 79-feature set.
    Designed for retraining verification (40% Attacks, 60% Benign).
    """
    print(f"Expert System: Synthesizing balanced dataset '{filename}'...")
    
    # Define Expert Feature List (79 Features + Metadata)
    features = [
        'Source IP', 'Destination IP', 'Protocol', 'Timestamp', 'Flow Duration', 
        'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 
        'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 
        'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 
        'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 
        'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 
        'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 
        'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 
        'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 
        'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 
        'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 
        'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 
        'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 
        'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 
        'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 
        'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 
        'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 
        'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 
        'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 
        'Idle Std', 'Idle Max', 'Idle Min', 'Label'
    ]

    num_attacks = int(entries * attack_ratio)
    num_benign = entries - num_attacks
    
    data = []
    
    # Generate Benign (60%)
    for i in range(num_benign):
        row = [f"192.168.1.{np.random.randint(2, 254)}", f"8.8.8.{np.random.randint(1, 20)}", 6, "2026-01-22 08:00:00"]
        # Random high-fidelity feature values for Benign
        row.extend(np.random.uniform(5, 50, len(features) - 5))
        row.append("BENIGN")
        data.append(row)
        
    # Generate Attacks (40%)
    attack_types = ["DoS", "PortScan", "BruteForce", "WebAttack"]
    for i in range(num_attacks):
        atk = np.random.choice(attack_types)
        row = [f"10.0.0.{np.random.randint(2, 254)}", f"172.16.0.{np.random.randint(1, 10)}", 6, "2026-01-22 08:05:00"]
        # Anomalous high-fidelity feature values for Attacks
        row.extend(np.random.uniform(500, 5000, len(features) - 5))
        row.append(atk)
        data.append(row)
        
    df = pd.DataFrame(data, columns=features)
    # Shuffle
    df = df.sample(frac=1).reset_index(drop=True)
    
    df.to_csv(filename, index=False)
    print(f"Expert System: Dataset '{filename}' generated successfully with {num_attacks} attacks and {num_benign} benign entries.")

if __name__ == "__main__":
    generate_balanced_dataset(r"D:\CDAC\project\new_v2\all_4060.csv", entries=50)
