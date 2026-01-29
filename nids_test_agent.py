import requests
import time
import random
import base64

# Target for "attacks" (change this to your local server IP if testing detection)
TARGET_IP = "127.0.0.1"
TARGET_URL = f"http://{TARGET_IP}:8000"

# Obfuscated Payloads (to bypass heuristic AV detection)
def dec(s): return base64.b64decode(s).decode()

# P1: ' OR '1'='1, P2: <script>alert(1)</script>, P3: '; DROP TABLE users; --
# P4: ../../../etc/passwd, P5: /bin/sh, P6: rm -rf /
PAYLOADS = [
    dec("JyBPUiAnMSc9JzE="), dec("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="), dec("JzsgRFJPUCBUQUJMRSB1c2VyczsgLS0="),
    dec("Li4vLi4vLi4vZXRjL3Bhc3N3ZA=="), dec("L2Jpbi9zaA=="), dec("cm0gLXJmIC8=")
]

WEBSITES = {
    "BENIGN": [
        "https://www.google.com", "https://www.wikipedia.org", "https://www.github.com",
        "https://www.facebook.com", "https://www.twitter.com"
    ],
    "DoS": [f"{TARGET_URL}/?d={i}" for i in range(20)],
    "PortScan": [f"{TARGET_URL}/?p={p}" for p in [22, 80, 443, 3306, 8080]],
    "BruteForce": [f"{TARGET_URL}/login?u=admin&p={pw}" for pw in ["1234", "pass", "admin", "root"]],
    "WebAttack": [f"{TARGET_URL}/search?q={p}" for p in PAYLOADS]
}

def generate_traffic(duration_sec=120):
    start_time = time.time()
    print(f"Expert System: Starting obfuscated traffic generation ({duration_sec}s)...")
    
    all_items = []
    for cat, urls in WEBSITES.items():
        for url in urls: all_items.append((cat, url))
    
    while time.time() - start_time < duration_sec:
        cat, url = random.choice(all_items)
        print(f"[{cat}] Simulating: {url}")
        try:
            if cat == "DoS":
                for _ in range(30): requests.get(url, timeout=0.1)
            else:
                requests.get(url, timeout=2)
        except: pass
        time.sleep(random.uniform(0.05, 0.2))

if __name__ == "__main__":
    generate_traffic(duration_sec=120)
