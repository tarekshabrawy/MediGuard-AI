# MediGuard AI

MediGuard AI is an IoT-based medical storage monitoring and cybersecurity threat detection system designed to monitor sensitive medical environments using AI and real-time sensor analysis.

The system connects a real ESP32 + DHT11 sensor with a Flask web application to monitor temperature, humidity, environmental conditions, and cybersecurity threats through separate Doctor and SOC dashboards.

---

# Features

- Real-time ESP32 sensor monitoring
- Temperature and humidity analysis
- Doctor dashboard for clinical monitoring
- SOC dashboard for cybersecurity monitoring
- AI-based anomaly detection
- Cyber attack simulation
- Dynamic vulnerability matrix
- Sensor isolation and restoration
- Event logging and monitoring
- Machine learning decision support

---

# Technologies Used

- Python
- Flask
- HTML / CSS / JavaScript
- ESP32
- DHT11 Sensor
- Scikit-learn
- Joblib

---

# AI Models

The system uses three machine learning models:

## 1. Condition Classification Model
Predicts:
- Normal
- Warning
- Critical

## 2. Anomaly Detection Model
Detects unusual or suspicious sensor behavior.

## 3. Attack Detection Model
Classifies:
- Environmental Failure
- Suspicious Behavior
- Possible Cyber Attack

---

# System Architecture

- Sensor Layer
- Communication Layer
- Flask Backend
- AI Analysis Layer
- Doctor Dashboard
- SOC Dashboard
- Storage Layer

---

# Project Structure

```bash
MediGuard-AI/
│
├── app.py
├── train_model.py
├── requirements.txt
├── static/
├── templates/
├── data/
├── logs.csv
├── README.md
└── docs/
```

---

# Installation

```bash
pip install -r requirements.txt
python app.py
```

---

# Future Improvements

- HTTPS / MQTT over TLS
- API authentication
- Replay attack protection
- Database integration
- Real-world dataset collection
- Advanced SOC analytics

---

# Author

Tarek Shabrawy
