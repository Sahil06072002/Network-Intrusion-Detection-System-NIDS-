# 🛡️ AI-Powered Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Django](https://img.shields.io/badge/Django-4.2-green.svg)
![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange.svg)
![License](https://img.shields.io/badge/license-DBDA-blue.svg)

## 📌 Overview

The **AI-Powered NIDS** is a comprehensive security solution designed to detect and analyze network anomalies in real-time. Leveraging machine learning algorithms (Decision Tree, Random Forest, etc.) trained on the **CICIDS2017** dataset, this system provides accurate classification of network traffic as benign or malicious.

It features a robust **Django** backend, a dynamic **Bootstrap 5** frontend, and a powerful **Dashboard** for visualization and reporting.

## ✨ Key Features

-   **🚀 Real-Time Detection**: Captures and analyzes live network packets using `Scapy` and ML models.
-   **📂 Offline Analysis**: Upload CSV traffic logs for bulk processing and threat detection.
-   **📊 Interactive Dashboard**: Visualizes attack trends, traffic distribution, and system health using `Chart.js`.
-   **🚨 Alert System**: Real-time logging of security alerts with severity levels and resolution tracking.
-   **📑 Automated Reporting**: Generates professional PDF reports of analysis results.
-   **🔐 Role-Based Access Control (RBAC)**: Secure authentication with distinct roles for Admins, Analysts, and Users.
-   **⚙️ Admin Panel**: Full control over users, models, and system logs via the customized Django Admin.

## 🛠️ Tech Stack

-   **Backend**: Django 4.2, Python 3.10
-   **Database**: MySQL
-   **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib
-   **Frontend**: HTML5, CSS3, Bootstrap 5, Chart.js
-   **Network**: Scapy (Packet Sniffing)
-   **Reporting**: xhtml2pdf

## 🚀 Installation & Setup

### Prerequisites
-   Python 3.10+
-   MySQL Server
-   Npcap (for Windows packet capture)

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/nids-project.git
cd nids-project
```

### 2. Create Virtual Environment
```bash
python -m venv nids_env
# Windows
nids_env\Scripts\activate
# Linux/Mac
source nids_env/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r rqrmnts.txt
```

### 4. Configure Environment
Create a `.env` file in `nids_backend/` with your database credentials:
```env
DEBUG=True
SECRET_KEY=your-secret-key
DATABASE_NAME=nids_db
DATABASE_USER=root
DATABASE_PASSWORD=your_password
DATABASE_HOST=localhost
DATABASE_PORT=3306
```

### 5. Database Setup
```bash
# Create database in MySQL first
python manage.py makemigrations
python manage.py migrate
```

### 6. Register ML Models
```bash
python manage.py register_models
```

### 7. Create Superuser
```bash
python manage.py createsuperuser
```

## 🖥️ Usage

### Running the Web Server
```bash
python manage.py runserver
```
Access the application at `http://127.0.0.1:8000/`.

### Running the Real-Time Sniffer
**Note**: Must be run with Administrator privileges.
```bash
python manage.py start_sniffer
```

## 📂 Project Structure

```
nids_project/
├── alerts/             # Alert management app
├── authentication/     # User auth & RBAC
├── dashboard/          # Analytics dashboard
├── detection/          # Core detection logic & views
├── ml_engine/          # ML model handling & feature extraction
├── models/             # Trained .pkl model files
├── nids_backend/       # Project settings
├── reports/            # PDF generation
├── templates/          # HTML templates
└── manage.py           # Django CLI utility
```

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## 📄 License

This project is licensed under the DBDA License.
