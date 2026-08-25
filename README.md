# MediGuard AI

MediGuard AI is an IoT-based medical storage monitoring and cybersecurity threat detection system designed to monitor sensitive medical environments using AI and real-time sensor analysis.

The system connects a real ESP32 sensor with a Flask web application to monitor temperature, humidity, environmental conditions, and cybersecurity threats through separate Doctor and SOC dashboards.

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

# Run the application

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`, then use the Doctor or SOC role from the login page.

## Testing Notes

The sensor API accepts JSON at `POST /api/sensor_reading`. The HMAC message remains:

```text
sensor_id|temperature|humidity|timestamp|nonce
```

Temperature and humidity must be formatted to two decimals in the HMAC message. The shared secret used by the current local prototype is `MEDIGUARD_SENSOR_SECRET_123`.

Example controlled local API security test script payload:

```json
{
	"sensor_id": "ESP32_ROOM_1",
	"temperature": 5.50,
	"humidity": 50.00,
	"timestamp": 1770000000,
	"nonce": "unique-test-nonce",
	"signature": "hexadecimal-hmac-sha256"
}
```

Optional hardware fields are accepted but are not part of the HMAC yet: `hardware_profile`, `local_alert`, `rtc_status`, `sd_backup_status`, and `dht22_temperature`.

Expected checks:

- Valid authenticated reading: HTTP 200 and updated dashboard values.
- Valid authenticated high temperature: environmental warning or critical cold-storage failure, not a cyber event.
- Invalid HMAC, replay nonce, unknown sensor, or invalid timestamp: HTTP 401 and a cybersecurity event.
- Malformed JSON or impossible sensor values: HTTP 400 and a cybersecurity event.
- Open `/clinical` as Doctor, `/soc` as SOC, `/logs` for event history, and `/verify_logs` for hash-chain verification.
- Capture evidence screenshots of a normal reading, environmental failure, rejected API request, SOC event state, and secure-log verification result. Use only actual results from the running system.

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
