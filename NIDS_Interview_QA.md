# NIDS Project - Interview Q&A Cheat Sheet

## 1. Project Overview

**Q: What is NIDS?**
> Network Intrusion Detection System. It monitors network traffic in real-time to detect malicious activity using Machine Learning.

**Q: What technologies did you use?**
> Django (Backend), Chart.js (Visualization), Scikit-learn (ML), Scapy (Packet Capture), SQLite/PostgreSQL (Database).

**Q: What is the goal of your project?**
> To build a web-based ML-powered security system that detects network attacks like DDoS, Port Scans, and Brute Force in real-time.

---

## 2. Machine Learning

**Q: What ML algorithms did you use?**
> Decision Tree (DT), Random Forest (RF), XGBoost, KNN. Each is trained on specific attack signatures.

**Q: Why use multiple models?**
> **Ensemble approach**. Different models are better at detecting different attacks. Using multiple models improves accuracy and reduces false negatives.

**Q: What dataset did you use?**
> CIC-IDS2017 (Canadian Institute for Cybersecurity). It contains labeled benign and attack traffic (DDoS, PortScan, BruteForce, etc.).

**Q: What is the detection rate?**
> Varies by model, but typically **95-99%** accuracy on test data, with real-world performance depending on traffic patterns.

**Q: What features are used for detection?**
> Flow Duration, Packet Length, Fwd/Bwd Packet counts, Protocol flags, Port numbers, Bytes/second, etc. (~79 features from CIC-IDS2017).

**Q: How do you handle class imbalance?**
> Used SMOTE (Synthetic Minority Oversampling), class weights, and stratified sampling during training.

---

## 3. System Architecture

**Q: Explain the system flow.**
> 1. Traffic captured (Scapy/CSV upload) → 2. Feature extraction → 3. ML prediction → 4. Results stored in DB → 5. Dashboard visualization.

**Q: What is the role of the "Detection Agent"?**
> Each agent is a specialized ML model trained on specific attack types. They work together in a pipeline to classify traffic.

**Q: What does `Fri_DDos_BEST_DT_CPU` mean?**
> `Fri_DDos` = trained on Friday DDoS data, `BEST` = optimized version, `DT` = Decision Tree algorithm, `CPU` = optimized for CPU execution.

**Q: How does real-time monitoring work?**
> A background sniffer (Scapy) captures packets, extracts features, runs ML predictions, and stores results. Dashboard polls via AJAX every 5 seconds.

---

## 4. Security Concepts

**Q: What is DDoS?**
> **Distributed Denial of Service**. An attack where multiple sources flood a target with traffic to make it unavailable.

**Q: What is a Port Scan?**
> An attacker probes open ports on a system to find vulnerabilities and entry points.

**Q: What is Brute Force?**
> Repeated login attempts using different username/password combinations to gain unauthorized access.

**Q: What is Botnet?**
> A network of compromised computers (bots) controlled by an attacker to perform coordinated attacks.

**Q: Difference between IDS and IPS?**
> **IDS** (Intrusion Detection) = Monitors and alerts. **IPS** (Intrusion Prevention) = Monitors and blocks.

---

## 5. Django & Web Development

**Q: Why Django?**
> Python-based, easy ML integration, built-in ORM, admin panel, authentication, and rapid development.

**Q: How is authentication handled?**
> Django's built-in auth system with custom User model. Role-based access (Admin, Analyst, User).

**Q: What is RBAC?**
> **Role-Based Access Control**. Admins see all data, Analysts see system-wide alerts, Users see only their uploads.

**Q: How are reports generated?**
> Using ReportLab library to create PDF summaries with detection stats and charts.

---

## 6. Database

**Q: What tables are in your database?**
> `User`, `UploadedTrafficFile`, `DetectionResult`, `AlertLog`, `MLModelMetadata`.

**Q: What is stored in DetectionResult?**
> Timestamp, Source/Dest IP, Prediction label, Confidence score, Model used, is_malicious flag.

---

## 7. Challenges & Solutions

**Q: What challenges did you face?**
> 1. Class imbalance → Used SMOTE
> 2. Real-time performance → Used lightweight DT models
> 3. False positives → Multi-model validation
> 4. Data privacy → Role-based access control

**Q: How do you ensure accuracy?**
> Cross-validation during training, confusion matrix analysis, precision/recall tuning, and real-world testing.

---

## 8. Future Enhancements

**Q: How would you improve this system?**
> 1. Deep Learning (LSTM for sequence analysis)
> 2. Integration with firewall for IPS capability
> 3. Cloud deployment for scalability
> 4. API for third-party SIEM integration

---

## Quick Stats to Remember
| Metric | Value |
|--------|-------|
| Total Models | 4-6 specialized agents |
| Features Used | ~79 from CIC-IDS2017 |
| Detection Rate | 95-99% |
| Dashboard Refresh | 5 seconds (AJAX) |
| Supported Attacks | DDoS, PortScan, BruteForce, Botnet, etc. |
