from flask import Flask, render_template, redirect, request, url_for, session, jsonify
import joblib
import csv
import os
import random
from datetime import datetime
import numpy as np
import sqlite3
import hashlib
import hmac
import time

DEV_MODE = False

app = Flask(__name__)
app.secret_key = "mediguard_demo_secret_key"

condition_model = joblib.load("condition_model.pkl")
anomaly_model = joblib.load("anomaly_model.pkl")
attack_model = joblib.load("attack_model.pkl")
try:
    anomaly_feature_columns = joblib.load('anomaly_feature_columns.pkl')
except Exception:
    anomaly_feature_columns = None

DEVICES_FILE = "data/devices.csv"
LOG_FILE = "logs.csv"
SECURE_DB = "secure_logs.db"
LOG_HEADER = [
    "timestamp","device_name","device_type","location","sensor_id",
    "temperature","humidity","ml_prediction","anomaly_prediction","anomaly_status",
    "risk_score","risk_level","recommended_action","attack_status","event_type","http_code"
]

TAMPER_DB = "tamper_incidents.db"
NONCE_DB = "nonce_store.db"
SHARED_SECRET = "MEDIGUARD_SENSOR_SECRET_123"
SECURITY_EVENT_ACTIVE_SECONDS = 60


def init_nonce_db():
    conn = sqlite3.connect(NONCE_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS used_nonces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sensor_id TEXT,
        nonce TEXT,
        timestamp INTEGER
    )''')
    conn.commit()
    conn.close()


def nonce_exists(sensor_id, nonce):
    conn = sqlite3.connect(NONCE_DB)
    c = conn.cursor()
    c.execute('SELECT 1 FROM used_nonces WHERE sensor_id = ? AND nonce = ? LIMIT 1', (sensor_id, nonce))
    row = c.fetchone()
    conn.close()
    return row is not None


def store_nonce(sensor_id, nonce, ts):
    try:
        conn = sqlite3.connect(NONCE_DB)
        c = conn.cursor()
        c.execute('INSERT INTO used_nonces (sensor_id, nonce, timestamp) VALUES (?,?,?)', (sensor_id, nonce, int(ts)))
        conn.commit()
        conn.close()
    except Exception:
        pass



def init_tamper_db():
    conn = sqlite3.connect(TAMPER_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS tamper_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detection_time TEXT,
        status TEXT,
        checked_logs INTEGER,
        first_tampered_log_id INTEGER,
        hash_algorithm TEXT,
        chain_type TEXT,
        description TEXT
    )''')
    conn.commit()
    conn.close()


def insert_tamper_incident(detection_time, status, checked_logs, first_tampered_log_id, hash_algorithm, chain_type, description):
    conn = sqlite3.connect(TAMPER_DB)
    c = conn.cursor()

    # Deduplicate: don't insert if latest incident for same first_tampered_log_id occurred within the same minute
    if first_tampered_log_id is not None:
        c.execute('''SELECT detection_time FROM tamper_incidents WHERE first_tampered_log_id = ? ORDER BY id DESC LIMIT 1''', (first_tampered_log_id,))
        row = c.fetchone()
        if row:
            try:
                prev_time = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                new_time = datetime.strptime(detection_time, "%Y-%m-%d %H:%M:%S")
                diff = (new_time - prev_time).total_seconds()
                if abs(diff) < 60:
                    conn.close()
                    return False
            except Exception:
                pass

    c.execute('''INSERT INTO tamper_incidents (
        detection_time, status, checked_logs, first_tampered_log_id, hash_algorithm, chain_type, description
    ) VALUES (?,?,?,?,?,?,?)''', (
        detection_time, status, int(checked_logs or 0), first_tampered_log_id if first_tampered_log_id is not None else None, hash_algorithm, chain_type, description
    ))

    conn.commit()
    conn.close()
    return True


def get_recent_tamper_incidents(limit=10):
    conn = sqlite3.connect(TAMPER_DB)
    c = conn.cursor()
    c.execute('''SELECT detection_time, status, checked_logs, first_tampered_log_id, hash_algorithm, chain_type, description FROM tamper_incidents ORDER BY id DESC LIMIT ?''', (limit,))
    rows = c.fetchall()
    conn.close()
    incidents = []
    for r in rows:
        incidents.append({
            'detection_time': r[0],
            'status': r[1],
            'checked_logs': r[2],
            'first_tampered_log_id': r[3],
            'hash_algorithm': r[4],
            'chain_type': r[5],
            'description': r[6]
        })
    return incidents


def init_secure_db():
    conn = sqlite3.connect(SECURE_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS secure_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        device_name TEXT,
        device_type TEXT,
        location TEXT,
        temperature REAL,
        humidity REAL,
        ml_prediction TEXT,
        anomaly_prediction INTEGER,
        anomaly_status TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        recommended_action TEXT,
        attack_status TEXT,
        previous_hash TEXT,
        current_hash TEXT
    )''')
    conn.commit()
    conn.close()


def compute_hash_for_entry(timestamp, device_name, temperature, humidity, ml_prediction, anomaly_status, risk_score, risk_level, attack_status, previous_hash):
    # Concatenate fields as strings in specified order and compute SHA-256
    parts = [
        str(timestamp),
        str(device_name),
        str(temperature),
        str(humidity),
        str(ml_prediction),
        str(anomaly_status),
        str(risk_score),
        str(risk_level),
        str(attack_status),
        str(previous_hash)
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def insert_secure_log_row(timestamp, device_name, device_type, location, temperature, humidity, ml_prediction, anomaly_prediction, anomaly_status, risk_score, risk_level, recommended_action, attack_status):
    conn = sqlite3.connect(SECURE_DB)
    c = conn.cursor()

    c.execute("SELECT current_hash FROM secure_logs ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    previous_hash = row[0] if row and row[0] else 'GENESIS'

    current_hash = compute_hash_for_entry(timestamp, device_name, temperature, humidity, ml_prediction, anomaly_status, risk_score, risk_level, attack_status, previous_hash)

    c.execute('''INSERT INTO secure_logs (
        timestamp, device_name, device_type, location, temperature, humidity,
        ml_prediction, anomaly_prediction, anomaly_status, risk_score, risk_level,
        recommended_action, attack_status, previous_hash, current_hash
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        timestamp, device_name, device_type, location, temperature, humidity,
        str(ml_prediction), int(anomaly_prediction), anomaly_status, int(risk_score), risk_level,
        recommended_action, attack_status, previous_hash, current_hash
    ))

    conn.commit()
    conn.close()


def verify_secure_logs():
    # Returns (is_valid, checked_count, first_tampered_id_or_None)
    conn = sqlite3.connect(SECURE_DB)
    c = conn.cursor()
    c.execute('SELECT id, timestamp, device_name, temperature, humidity, ml_prediction, anomaly_status, risk_score, risk_level, attack_status, previous_hash, current_hash FROM secure_logs ORDER BY id ASC')
    rows = c.fetchall()
    conn.close()

    prev_hash = None
    checked = 0
    first_tampered = None

    for r in rows:
        checked += 1
        rid, timestamp, device_name, temperature, humidity, ml_prediction, anomaly_status, risk_score, risk_level, attack_status, previous_prev_hash, current_hash = r

        # verify previous_hash matches prev_hash (or GENESIS for first)
        expected_prev = prev_hash if prev_hash is not None else 'GENESIS'
        if str(previous_prev_hash) != str(expected_prev):
            if first_tampered is None:
                first_tampered = rid
            prev_hash = current_hash
            continue

        # recompute current hash
        recomputed = compute_hash_for_entry(timestamp, device_name, temperature, humidity, ml_prediction, anomaly_status, risk_score, risk_level, attack_status, previous_prev_hash)

        if recomputed != current_hash:
            if first_tampered is None:
                first_tampered = rid
            prev_hash = current_hash
            continue

        prev_hash = current_hash

    is_valid = first_tampered is None

    # If tampering detected, record a tamper incident
    try:
        if not is_valid:
            detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            hash_algorithm = "SHA-256"
            chain_type = "Previous-hash linked audit trail"
            description = "Audit log integrity violation detected using SHA-256 hash-chain verification."
            insert_tamper_incident(detection_time, "TAMPERED", checked, first_tampered, hash_algorithm, chain_type, description)
            record_security_event(
                "Message Tampering",
                sensor_id="secure_logs.db",
                temperature=None,
                humidity=None,
                risk_score=100,
                risk_level="High",
                recommended_action="Review audit trail and restore hash-chain integrity",
                http_code=500
            )
    except Exception:
        pass

    return is_valid, checked, first_tampered


# initialize secure DB at import
init_secure_db()
init_tamper_db()
init_nonce_db()

# Trusted ESP32 identity
TRUSTED_SENSOR_ID = "ESP32_ROOM_1"
TRUSTED_SENSOR_TOKEN = "MEDIGUARD_SENSOR_SECRET_123"


def require_login(role=None):
    if "role" not in session:
        return False
    if role and session.get("role") != role:
        return False
    return True


def get_fieldnames():
    return [
        "device_name", "device_type", "location", "storage_type",
        "temperature_c", "humidity", "object_temperature", "cooling_status",
        "status", "risk_score", "risk_level", "action",
        "environment_reason",
        "ml_prediction", "anomaly_status", "attack_status",
        "security_status", "isolation_status",
        "behavior_status", "behavior_reason",
        "attack_type", "attack_reason",
        "last_temperature", "last_humidity", "repeat_count", "last_seen",
        "last_security_event_time", "last_valid_reading_time"
    ]


def create_default_sensor():
    os.makedirs("data", exist_ok=True)

    default_device = {
        "device_name": "Real ESP32 Room Sensor",
        "device_type": "temperature_humidity_sensor",
        "location": "Demo Room",
        "storage_type": "Room Monitoring",
        "temperature_c": "",
        "humidity": "",
        "object_temperature": "",
        "cooling_status": "",
        "status": "No Data",
        "risk_score": 0,
        "risk_level": "-",
        "action": "-",
        "environment_reason": "-",
        "ml_prediction": "-",
        "anomaly_status": "-",
        "attack_status": "-",
        "security_status": "Secure",
        "isolation_status": "Active",
        "behavior_status": "-",
        "behavior_reason": "-",
        "attack_type": "-",
        "attack_reason": "-",
        "last_temperature": "",
        "last_humidity": "",
        "repeat_count": 0,
        "last_seen": "",
        "last_security_event_time": "",
        "last_valid_reading_time": ""
    }

    with open(DEVICES_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=get_fieldnames())
        writer.writeheader()
        writer.writerow(default_device)


def ensure_single_sensor():
    if not os.path.exists(DEVICES_FILE):
        create_default_sensor()
        return

    with open(DEVICES_FILE, "r", newline="") as file:
        devices = list(csv.DictReader(file))

    if len(devices) == 0:
        create_default_sensor()
        return

    device = devices[0]
    cleaned = {}

    for field in get_fieldnames():
        cleaned[field] = device.get(field, "")

    cleaned["device_name"] = "Real ESP32 Room Sensor"
    cleaned["device_type"] = "temperature_humidity_sensor"
    cleaned["location"] = "Demo Room"
    cleaned["storage_type"] = "Room Monitoring"

    with open(DEVICES_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=get_fieldnames())
        writer.writeheader()
        writer.writerow(cleaned)


def load_devices():
    ensure_single_sensor()
    devices = []

    with open(DEVICES_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            devices.append({
                "device_name": row.get("device_name", ""),
                "device_type": row.get("device_type", ""),
                "location": row.get("location", ""),
                "storage_type": row.get("storage_type", ""),
                "temperature_c": row.get("temperature_c") or "-",
                "humidity": row.get("humidity") or "-",
                "object_temperature": row.get("object_temperature") or "-",
                "cooling_status": row.get("cooling_status") or "-",
                "status": row.get("status") or "No Data",
                "risk_score": int(float(row.get("risk_score") or 0)),
                "risk_level": row.get("risk_level") or "-",
                "action": row.get("action") or "-",
                "environment_reason": row.get("environment_reason") or "-",
                "ml_prediction": row.get("ml_prediction") or "-",
                "anomaly_status": row.get("anomaly_status") or "-",
                "attack_status": row.get("attack_status") or "-",
                "security_status": row.get("security_status") or "Secure",
                "isolation_status": row.get("isolation_status") or "Active",
                "behavior_status": row.get("behavior_status") or "-",
                "behavior_reason": row.get("behavior_reason") or "-",
                "attack_type": row.get("attack_type") or "-",
                "attack_reason": row.get("attack_reason") or "-",
                "last_temperature": row.get("last_temperature") or "",
                "last_humidity": row.get("last_humidity") or "",
                "repeat_count": int(row.get("repeat_count") or 0),
                "last_seen": row.get("last_seen") or "",
                "last_security_event_time": row.get("last_security_event_time") or "",
                "last_valid_reading_time": row.get("last_valid_reading_time") or ""
            })

    return devices


def save_devices(devices):
    os.makedirs("data", exist_ok=True)

    with open(DEVICES_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=get_fieldnames())
        writer.writeheader()
        writer.writerows(devices)


def update_device_readings(device_index, updated_data):
    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return

    for key, value in updated_data.items():
        devices[device_index][key] = value

    save_devices(devices)


def is_recent_security_event(device):
    if not device:
        return False

    last_event = device.get("last_security_event_time") or ""
    if not last_event:
        return False

    try:
        parsed = datetime.strptime(last_event, "%Y-%m-%d %H:%M:%S")
    except Exception:
        try:
            parsed = datetime.fromtimestamp(float(last_event))
        except Exception:
            return False

    return (datetime.now() - parsed).total_seconds() <= SECURITY_EVENT_ACTIVE_SECONDS


def refresh_security_event_state(devices):
    for device in devices:
        if device.get("isolation_status") == "Isolated":
            device["security_status"] = "Isolated"
            continue

        if not is_recent_security_event(device):
            if device.get("attack_status") in ["Possible Cyber Attack", "Security Event Detected"]:
                device["attack_status"] = "Normal Operation"
            if device.get("security_status") in ["Under Attack", "Suspicious"]:
                device["security_status"] = "Secure"
            if device.get("attack_type") in ["Malformed Sensor Request", "Invalid Sensor Signature", "Replay Attack", "Old Timestamp", "Invalid API Payload", "Unauthorized Sensor Spoofing", "Impossible Sensor Payload", "Sensor Availability Failure", "Invalid Sensor Data Type", "Security Event Detected"]:
                device["attack_type"] = "-"
            if device.get("attack_reason") and device.get("attack_reason") not in ["-", ""]:
                reason = device.get("attack_reason")
                if reason.startswith("Missing fields") or "signature" in reason.lower() or "replay" in reason.lower() or "timestamp" in reason.lower() or "unknown sensor" in reason.lower() or "payload" in reason.lower() or "malformed" in reason.lower():
                    device["attack_reason"] = "-"
        else:
            device["security_status"] = "Under Attack"
            if device.get("attack_status") not in ["Possible Cyber Attack", "Security Event Detected"]:
                device["attack_status"] = "Security Event Detected"

    return devices


def check_sensor_availability(devices):
    updated = False
    now = datetime.now()

    for device in devices:
        isolation_status = device.get("isolation_status", "Active")

        if isolation_status == "Isolated":
            continue

        last_seen = device.get("last_seen", "")

        if not last_seen:
            continue

        try:
            last_seen_time = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
        except:
            continue

        seconds_offline = (now - last_seen_time).total_seconds()

        if seconds_offline >= 40:
            device["status"] = "Critical"
            device["risk_score"] = 85
            device["risk_level"] = "High"
            device["action"] = "Check ESP32 power, Wi-Fi, and sensor wiring immediately"
            device["environment_reason"] = "No sensor readings received for more than 40 seconds"

            device["anomaly_status"] = "Anomalous"
            device["attack_status"] = "Sensor Disconnected"
            device["security_status"] = "Sensor Disconnected"
            device["behavior_status"] = "Sensor Disconnected"
            device["behavior_reason"] = "The ESP32 stopped sending live readings for a critical timeout period"

            device["attack_type"] = "Sensor Availability Failure"
            device["attack_reason"] = "Sensor may be disconnected, powered off, Wi-Fi lost, or under availability attack"
            record_security_event(
                "Sensor Offline",
                sensor_id=device.get("device_name") or "ESP32_ROOM_1",
                temperature=device.get("temperature_c") if str(device.get("temperature_c") or "").replace("-", "").replace(".", "").isdigit() or (str(device.get("temperature_c") or "").startswith("-") and str(device.get("temperature_c") or "") [1:].replace(".", "").isdigit()) else None,
                humidity=device.get("humidity") if str(device.get("humidity") or "").replace(".", "").isdigit() else None,
                risk_score=85,
                risk_level="High",
                recommended_action="Check ESP32 power, Wi-Fi, and sensor wiring immediately",
                http_code=503
            )

            updated = True

        elif seconds_offline >= 15:
            device["status"] = "Warning"
            device["risk_score"] = 55
            device["risk_level"] = "Medium"
            device["action"] = "Check ESP32 connection"
            device["environment_reason"] = "No sensor readings received for more than 15 seconds"

            device["anomaly_status"] = "Anomalous"
            device["attack_status"] = "Availability Warning"
            device["security_status"] = "Availability Warning"
            device["behavior_status"] = "Availability Warning"
            device["behavior_reason"] = "Sensor heartbeat delay detected"

            device["attack_type"] = "Sensor Availability Warning"
            device["attack_reason"] = "The sensor stopped sending readings within the expected time window"

            updated = True

    if updated:
        save_devices(devices)

    return devices


def get_dashboard_stats(devices):
    total = len(devices)
    normal = sum(1 for d in devices if d.get("status") == "Normal")
    warning = sum(1 for d in devices if d.get("status") == "Warning")
    critical = sum(1 for d in devices if d.get("status") == "Critical")
    anomalies = sum(1 for d in devices if d.get("anomaly_status") == "Anomalous")
    attacks = sum(1 for d in devices if is_recent_security_event(d))
    isolated = sum(1 for d in devices if d.get("isolation_status") == "Isolated")
    avg_risk = round(sum(int(d.get("risk_score") or 0) for d in devices) / total, 1) if total else 0

    return {
        "total": total,
        "normal": normal,
        "warning": warning,
        "critical": critical,
        "anomalies": anomalies,
        "attacks": attacks,
        "isolated": isolated,
        "avg_risk": avg_risk
    }


def calculate_environmental_result(behavior, ml_prediction, anomaly_flag):
    # Cold-storage thresholds:
    # Normal: 2-8°C
    # Warning: 8-12.5°C
    # Critical: >=13°C
    temp = behavior["temp_c"]
    humidity = behavior["humidity"]

    risk_score = 0
    reasons = []

    # Temperature contribution
    if 2.0 <= temp <= 8.0:
        reasons.append("Temperature within cold-storage target (2-8°C)")
        risk_score += 5
    elif 8.0 < temp < 13.0:
        reasons.append("Temperature slightly outside safe cold-storage range")
        risk_score += 40
    else:  # temp <2 or temp >=13
        reasons.append("Temperature in critical cold-storage range")
        risk_score += 80

    # Humidity contribution (acceptable roughly 30-80%)
    if 30 <= humidity <= 80:
        reasons.append("Humidity within acceptable range")
        risk_score += 5
    elif 20 <= humidity < 30 or 80 < humidity <= 90:
        reasons.append("Humidity slightly outside acceptable range")
        risk_score += 25
    else:
        reasons.append("Humidity critically outside acceptable range")
        risk_score += 60

    # ML model influence
    try:
        if isinstance(ml_prediction, str):
            if ml_prediction.lower() == 'warning':
                risk_score += 5
                reasons.append('Model predicted Warning')
            elif ml_prediction.lower() == 'critical' or ml_prediction.lower() == 'possible_failure':
                risk_score += 25
                reasons.append('Model predicted Critical')
        else:
            # numeric legacy: treat 1 as critical
            if ml_prediction == 1:
                risk_score += 25
                reasons.append('Model predicted Critical')
    except Exception:
        pass

    if anomaly_flag == 1:
        risk_score += 10
        reasons.append("Suspicious data behavior detected")

    risk_score = min(int(risk_score), 100)
    reason_text = "; ".join(reasons)

    # Decide status
    if temp >= 13.0 or humidity < 20 or humidity > 90 or risk_score >= 70:
        return "Critical", "High", "Critical Cold-Storage Failure", risk_score, reason_text
    elif 8.0 < temp < 13.0 or humidity < 30 or humidity > 80 or risk_score >= 30:
        return "Warning", "Medium", "Cold-Storage Warning", risk_score, reason_text
    else:
        return "Normal", "Low", "Continue Monitoring", risk_score, reason_text


def make_features(behavior):
    return [[
        behavior["serial_reading"],
        behavior["temp_c"],
        behavior["temp_fh"],
        behavior["humidity"],
        behavior["object_temp"],
        behavior["nw_cooling"]
    ]]


def get_condition_prediction(behavior):
    # return string label when model uses string classes
    pred = condition_model.predict(make_features(behavior))[0]
    try:
        return str(pred)
    except:
        return pred


def get_anomaly_status(behavior):
    # Prefer time-series features when available
    try:
        if anomaly_feature_columns is not None:
            feat = compute_anomaly_features_for_behavior(behavior)
            X = [feat]
            pred = anomaly_model.predict(X)[0]
            # IsolationForest: -1 -> anomaly; Classifier: 1 -> anomaly
            try:
                if int(pred) == 1:
                    return "Anomalous", 1
            except Exception:
                if pred == -1:
                    return "Anomalous", 1
            return "Normal Pattern", 0
    except Exception:
        pass

    # fallback: legacy single-point anomaly check
    prediction = anomaly_model.predict(make_features(behavior))[0]
    if prediction == -1:
        return "Anomalous", 1
    try:
        if int(prediction) == 1:
            return "Anomalous", 1
    except Exception:
        pass
    return "Normal Pattern", 0


def compute_anomaly_features_for_behavior(behavior, window_size=5):
    # Read recent log lines for this device to build a rolling window
    temps = []
    hums = []
    device_name = None
    try:
        device_name = behavior.get('device_name') or behavior.get('device', {}).get('device_name')
    except Exception:
        device_name = None

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r', newline='') as f:
                reader = csv.DictReader(f)
                rows = [r for r in reader if (device_name is None or r.get('device_name') == device_name)]
                tail = rows[-(window_size - 1):] if len(rows) >= (window_size - 1) else rows
                for r in tail:
                    try:
                        temps.append(float(r.get('temperature') or r.get('temperature_c') or r.get('temp_c')))
                    except Exception:
                        pass
                    try:
                        hums.append(float(r.get('humidity')))
                    except Exception:
                        pass
        except Exception:
            temps = []
            hums = []

    # append current reading
    try:
        temps.append(float(behavior['temp_c']))
    except Exception:
        temps.append(0.0)
    try:
        hums.append(float(behavior['humidity']))
    except Exception:
        hums.append(0.0)

    # ensure window_size length
    if len(temps) < window_size:
        temps = [temps[0]] * (window_size - len(temps)) + temps
    if len(hums) < window_size:
        hums = [hums[0]] * (window_size - len(hums)) + hums

    current_t = float(temps[-1])
    current_h = float(hums[-1])
    prev_t = float(temps[-2])
    prev_h = float(hums[-2])

    temp_change = current_t - prev_t
    hum_change = current_h - prev_h

    rt_mean = float(np.mean(temps))
    rh_mean = float(np.mean(hums))
    rt_std = float(np.std(temps))
    rh_std = float(np.std(hums))

    try:
        idx = np.arange(window_size)
        t_slope = float(np.polyfit(idx, temps, 1)[0])
        h_slope = float(np.polyfit(idx, hums, 1)[0])
    except Exception:
        t_slope = 0.0
        h_slope = 0.0

    feat = [
        current_t, current_h, temp_change, hum_change,
        rt_mean, rh_mean, rt_std, rh_std,
        t_slope, h_slope
    ]

    return feat


def get_attack_model_decision(environmental_risk, vulnerability_score, anomaly_flag, ml_prediction):
    # attack model expects a critical flag as the 4th feature
    try:
        critical_flag = 1 if (isinstance(ml_prediction, str) and ml_prediction.lower() == 'critical') else (1 if int(ml_prediction) == 1 else 0)
    except Exception:
        critical_flag = 0

    features = [[environmental_risk, vulnerability_score, anomaly_flag, critical_flag]]
    return attack_model.predict(features)[0]


def analyze_sensor_behavior(device, behavior):
    reasons = []
    suspicious = False

    current_temp = behavior["temp_c"]
    current_humidity = behavior["humidity"]
    object_temp = behavior["object_temp"]

    try:
        last_temp = float(device.get("temperature_c"))
        last_humidity = float(device.get("humidity"))
    except:
        last_temp = None
        last_humidity = None

    repeat_count = int(device.get("repeat_count") or 0)

    if last_temp is not None:
        temp_jump = abs(current_temp - last_temp)
        if temp_jump >= 35:
            suspicious = True
            reasons.append("Physically impossible sudden temperature jump")

    if last_humidity is not None:
        humidity_jump = abs(current_humidity - last_humidity)
        if humidity_jump >= 70:
            suspicious = True
            reasons.append("Physically impossible sudden humidity jump")

    if abs(object_temp - current_temp) >= 18:
        suspicious = True
        reasons.append("Sensor temperature and object temperature are inconsistent")

    if last_temp is not None and last_humidity is not None:
        if current_temp == last_temp and current_humidity == last_humidity:
            repeat_count += 1
        else:
            repeat_count = 0

    if suspicious:
        return "Suspicious Behavior", "; ".join(reasons), 1, repeat_count

    return "Normal Behavior", "Pattern is consistent with real physical sensor behavior", 0, repeat_count


def get_vulnerability_risks(devices):
    risk_rows = [
        {"id": "V1", "threat": "Unauthorized sensor spoofing", "implemented_control": "HMAC-SHA-256 sensor authentication", "likelihood": 1, "impact": 4, "score": 4, "risk_percentage": 16, "residual_risk": "Low", "recommendation": "Keep sensor secret protected"},
        {"id": "V2", "threat": "Missing or invalid sensor signature", "implemented_control": "HMAC signature verification", "likelihood": 1, "impact": 4, "score": 4, "risk_percentage": 16, "residual_risk": "Low", "recommendation": "Log rejected requests as security events"},
        {"id": "V3", "threat": "Replay of old sensor readings", "implemented_control": "Timestamp and nonce validation", "likelihood": 1, "impact": 4, "score": 4, "risk_percentage": 16, "residual_risk": "Low", "recommendation": "Store nonce history persistently"},
        {"id": "V4", "threat": "Message tampering in transit", "implemented_control": "HMAC-SHA-256 integrity check", "likelihood": 1, "impact": 4, "score": 4, "risk_percentage": 16, "residual_risk": "Low", "recommendation": "Add HTTPS/TLS in future"},
        {"id": "V5", "threat": "Unencrypted communication", "implemented_control": "HMAC protects integrity but not confidentiality", "likelihood": 3, "impact": 3, "score": 9, "risk_percentage": 36, "residual_risk": "Medium", "recommendation": "Use HTTPS/TLS or MQTT over TLS"},
        {"id": "V6", "threat": "Impossible sensor values", "implemented_control": "Input validation and cold-storage thresholds", "likelihood": 2, "impact": 3, "score": 6, "risk_percentage": 24, "residual_risk": "Medium", "recommendation": "Add stricter validation for medical-grade deployment"},
        {"id": "V7", "threat": "Abnormal sensor behavior", "implemented_control": "AI anomaly detection model", "likelihood": 2, "impact": 4, "score": 8, "risk_percentage": 32, "residual_risk": "Medium", "recommendation": "Validate with more real-world failure and attack data"},
        {"id": "V8", "threat": "Manual log modification", "implemented_control": "SHA-256 hash-chain secure audit logs", "likelihood": 1, "impact": 5, "score": 5, "risk_percentage": 20, "residual_risk": "Low", "recommendation": "Protect database access and backups"},
        {"id": "V9", "threat": "Tamper incident loss", "implemented_control": "Tamper incident recording", "likelihood": 1, "impact": 4, "score": 4, "risk_percentage": 16, "residual_risk": "Low", "recommendation": "Add exportable incident reports later"},
        {"id": "V10", "threat": "Sensor disconnection or availability loss", "implemented_control": "Last-seen monitoring and dashboard visibility", "likelihood": 4, "impact": 5, "score": 20, "risk_percentage": 80, "residual_risk": "Critical", "recommendation": "Add heartbeat alerts and notification escalation"},
        {"id": "V11", "threat": "API flooding or DDoS", "implemented_control": "Not fully implemented in prototype", "likelihood": 4, "impact": 4, "score": 16, "risk_percentage": 64, "residual_risk": "High", "recommendation": "Add rate limiting and request throttling"},
        {"id": "V12", "threat": "Gateway or laptop compromise", "implemented_control": "Outside prototype scope", "likelihood": 2, "impact": 5, "score": 10, "risk_percentage": 40, "residual_risk": "Medium", "recommendation": "Add endpoint protection and access restrictions"},
        {"id": "V13", "threat": "SOC response delay", "implemented_control": "SOC isolate/restore controls", "likelihood": 2, "impact": 4, "score": 8, "risk_percentage": 32, "residual_risk": "Medium", "recommendation": "Add incident workflow export and response tracking"},
    ]

    for item in risk_rows:
        item["risk_level"] = item["residual_risk"]
        item["related"] = False
        item["matrix_mode"] = "residual_risk"
        item["active_attack_type"] = "-"

    return risk_rows


def get_vulnerability_percentage(vulnerability_risks):
    if not vulnerability_risks:
        return 0

    percentages = [risk.get("risk_percentage", max(0, min(100, round((risk.get("score", 0) / 25) * 100)))) for risk in vulnerability_risks]
    return round(sum(percentages) / len(percentages))


def get_risk_level_from_percentage(percentage):
    if percentage >= 80:
        return "Critical"
    elif percentage >= 60:
        return "High"
    elif percentage >= 30:
        return "Medium"
    else:
        return "Low"


def get_security_status(attack_status, anomaly_status, isolation_status):
    if isolation_status == "Isolated":
        return "Isolated"
    if attack_status in ["Possible Cyber Attack", "Security Event Detected"]:
        return "Under Attack"
    if attack_status in ["Sensor Disconnected", "Availability Warning"]:
        return "Sensor Offline"
    if anomaly_status == "Anomalous":
        return "Suspicious"
    return "Secure"


def trigger_external_attack(device_index, attack_type, attack_reason, sensor_id=None, temperature=None, humidity=None, http_code=None):
    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return False

    temp_devices = [dict(d) for d in devices]
    temp_devices[device_index]["attack_status"] = "Security Event Detected"
    temp_devices[device_index]["security_status"] = "Under Attack"
    temp_devices[device_index]["anomaly_status"] = "Anomalous"
    temp_devices[device_index]["behavior_status"] = "Suspicious Behavior"
    temp_devices[device_index]["attack_type"] = attack_type
    temp_devices[device_index]["attack_reason"] = attack_reason
    temp_devices[device_index]["last_security_event_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    vulnerability_risks = get_vulnerability_risks(temp_devices)
    vulnerability_percentage = get_vulnerability_percentage(vulnerability_risks)
    risk_level = get_risk_level_from_percentage(vulnerability_percentage)

    updated_data = {
        "attack_status": "Security Event Detected",
        "security_status": "Under Attack",
        "anomaly_status": "Anomalous",
        "behavior_status": "Suspicious Behavior",
        "behavior_reason": attack_reason,
        "attack_type": attack_type,
        "attack_reason": attack_reason,
        "risk_score": vulnerability_percentage,
        "risk_level": risk_level,
        "action": "SOC Investigation Required",
        "last_security_event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    record_security_event(
        attack_type,
        sensor_id=sensor_id or devices[device_index].get("device_name") or "Unknown sensor",
        temperature=temperature,
        humidity=humidity,
        risk_score=vulnerability_percentage,
        risk_level=risk_level,
        recommended_action="SOC Investigation Required",
        http_code=http_code
    )

    update_device_readings(device_index, updated_data)
    return True


def ensure_log_file_schema():
    file_exists = os.path.exists(LOG_FILE)
    if file_exists:
        try:
            with open(LOG_FILE, "r", newline="") as file:
                reader = csv.reader(file)
                rows = list(reader)
            if rows and rows[0] == LOG_HEADER:
                return
            if rows:
                with open(LOG_FILE, "w", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow(LOG_HEADER)
                    for row in rows[1:]:
                        if len(row) >= len(LOG_HEADER):
                            writer.writerow(row[:len(LOG_HEADER)])
                        else:
                            writer.writerow(row + [""] * (len(LOG_HEADER) - len(row)))
                return
        except Exception:
            pass

    with open(LOG_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(LOG_HEADER)


def record_security_event(event_type, sensor_id=None, temperature=None, humidity=None, risk_score=0, risk_level="Low", recommended_action="Review event", http_code=None):
    ensure_log_file_schema()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            sensor_id or "Unknown sensor",
            "ESP32",
            "External",
            sensor_id or "",
            temperature if temperature is not None else "",
            humidity if humidity is not None else "",
            "-",
            0,
            "Security Event",
            int(risk_score if risk_score is not None else 0),
            risk_level or "Low",
            recommended_action or "Review event",
            event_type,
            event_type,
            http_code if http_code is not None else ""
        ])

    try:
        insert_secure_log_row(
            timestamp,
            sensor_id or "Unknown sensor",
            "ESP32",
            "External",
            float(temperature) if temperature is not None else 0.0,
            float(humidity) if humidity is not None else 0.0,
            "Security Event",
            0,
            "Security Event",
            int(risk_score if risk_score is not None else 0),
            risk_level or "Low",
            recommended_action or "Review event",
            event_type
        )
    except Exception:
        pass


def save_log(device, behavior, ml_prediction, anomaly_status, risk_score, risk_level, action, attack_status):
    # Ensure logs use the standardized header required by the project
    file_exists = os.path.exists(LOG_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "timestamp","device_name","device_type","location",
                "temperature","humidity","ml_prediction","anomaly_prediction","anomaly_status",
                "risk_score","risk_level","recommended_action","attack_status"
            ])

        # anomaly_prediction: numeric flag if model flagged anomaly
        try:
            anomaly_pred_flag = 1 if anomaly_status == "Anomalous" else 0
        except:
            anomaly_pred_flag = 0

        writer.writerow([
            timestamp,
            device.get("device_name", ""),
            device.get("device_type", ""),
            device.get("location", ""),
            behavior.get("temp_c"),
            behavior.get("humidity"),
            ml_prediction,
            anomaly_pred_flag,
            anomaly_status,
            risk_score,
            risk_level,
            action,
            attack_status
        ])

    # Also insert into secure SQLite audit log with hash-chain
    try:
        insert_secure_log_row(
            timestamp,
            device.get("device_name", ""),
            device.get("device_type", ""),
            device.get("location", ""),
            float(behavior.get("temp_c") if behavior.get("temp_c") is not None else 0.0),
            float(behavior.get("humidity") if behavior.get("humidity") is not None else 0.0),
            ml_prediction,
            anomaly_pred_flag,
            anomaly_status,
            int(risk_score if risk_score is not None else 0),
            risk_level,
            action,
            attack_status
        )
    except Exception:
        # ensure we don't break core logging on DB failure
        pass


def process_device_reading(device_index, behavior, simulated_attack=False, attack_type="-", attack_reason="-"):
    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return False

    device = devices[device_index]

    if device.get("isolation_status") == "Isolated" and not simulated_attack:
        return False

    ml_prediction = get_condition_prediction(behavior)
    model_anomaly_status, model_anomaly_flag = get_anomaly_status(behavior)

    behavior_status, behavior_reason, behavior_anomaly_flag, repeat_count = analyze_sensor_behavior(device, behavior)

    already_under_attack = device.get("attack_status") == "Possible Cyber Attack"

    if simulated_attack or already_under_attack:
        anomaly_flag = 1
    elif behavior_anomaly_flag == 1:
        anomaly_flag = 1
    else:
        anomaly_flag = 0

    anomaly_status = "Anomalous" if anomaly_flag else "Normal Pattern"

    status, risk_level, action, environmental_risk_score, environment_reason = calculate_environmental_result(
        behavior, ml_prediction, anomaly_flag
    )

    temp_devices = [dict(d) for d in devices]
    temp_devices[device_index]["anomaly_status"] = anomaly_status
    temp_devices[device_index]["behavior_status"] = "Suspicious Behavior" if simulated_attack or already_under_attack else behavior_status

    if simulated_attack:
        temp_devices[device_index]["attack_status"] = "Possible Cyber Attack"
        temp_devices[device_index]["attack_type"] = attack_type
    elif already_under_attack:
        temp_devices[device_index]["attack_status"] = "Possible Cyber Attack"
        temp_devices[device_index]["attack_type"] = device.get("attack_type") or "Active Cyber Incident"
    else:
        temp_devices[device_index]["attack_status"] = "Normal Operation"
        temp_devices[device_index]["attack_type"] = "-"

    vulnerability_risks = get_vulnerability_risks(temp_devices)
    vulnerability_percentage = get_vulnerability_percentage(vulnerability_risks)

    attack_ai_decision = get_attack_model_decision(
        environmental_risk_score,
        vulnerability_percentage,
        anomaly_flag,
        ml_prediction
    )

    if simulated_attack:
        attack_status = "Possible Cyber Attack"
    elif already_under_attack:
        attack_status = "Possible Cyber Attack"
    elif status == "Critical":
        attack_status = "Critical Cold-Storage Failure"
    elif status == "Warning":
        attack_status = "Cold-Storage Warning"
    else:
        attack_status = "Normal Operation"

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not simulated_attack and not already_under_attack and attack_status == "Normal Operation":
        temp_devices[device_index]["last_valid_reading_time"] = current_time
        temp_devices[device_index]["last_security_event_time"] = ""

    isolation_status = device.get("isolation_status") or "Active"
    security_status = get_security_status(attack_status, anomaly_status, isolation_status)

    if simulated_attack:
        final_behavior_status = "Suspicious Behavior"
        final_behavior_reason = attack_reason
        final_attack_type = attack_type
        final_attack_reason = attack_reason
    elif already_under_attack:
        final_behavior_status = "Suspicious Behavior"
        final_behavior_reason = device.get("behavior_reason") or "Active cyber incident remains unresolved"
        final_attack_type = device.get("attack_type") or "Active Cyber Incident"
        final_attack_reason = device.get("attack_reason") or "Attack persists until SOC isolate/restore action"
    else:
        final_behavior_status = behavior_status
        final_behavior_reason = behavior_reason
        final_attack_type = "-"
        final_attack_reason = "-"

    if attack_status == "Possible Cyber Attack":
        final_risk_score = vulnerability_percentage
        final_risk_level = get_risk_level_from_percentage(final_risk_score)
    else:
        final_risk_score = environmental_risk_score
        final_risk_level = risk_level

    updated_data = {
        "temperature_c": behavior["temp_c"],
        "humidity": behavior["humidity"],
        "object_temperature": behavior["object_temp"],
        "cooling_status": "Normal" if behavior["nw_cooling"] == 0 else "Failure",
        "status": status,
        "risk_score": final_risk_score,
        "risk_level": final_risk_level,
        "action": action,
        "environment_reason": environment_reason,
        "ml_prediction": ml_prediction,
        "anomaly_status": anomaly_status,
        "attack_status": attack_status,
        "security_status": security_status,
        "isolation_status": isolation_status,
        "behavior_status": final_behavior_status,
        "behavior_reason": final_behavior_reason,
        "attack_type": final_attack_type,
        "attack_reason": final_attack_reason,
        "last_temperature": behavior["temp_c"],
        "last_humidity": behavior["humidity"],
        "repeat_count": repeat_count,
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_valid_reading_time": current_time,
        "last_security_event_time": "" if (not simulated_attack and not already_under_attack and attack_status == "Normal Operation") else device.get("last_security_event_time", "")
    }

    update_device_readings(device_index, updated_data)

    save_log(
        device,
        behavior,
        ml_prediction,
        anomaly_status,
        final_risk_score,
        final_risk_level,
        action,
        attack_status
    )

    return True


def generate_attack_reading(current_device):
    try:
        previous_temp = float(current_device.get("temperature_c"))
        previous_humidity = float(current_device.get("humidity"))
    except:
        previous_temp = 27.0
        previous_humidity = 50.0

    attack_type = random.choice([
        "Data Spoofing Attack",
        "Man-in-the-Middle Observation",
        "Replay Attack",
        "DDoS / Flooding Attempt",
        "Malware Data Manipulation",
        "Sensor Identity Spoofing"
    ])

    if attack_type == "Data Spoofing Attack":
        temp_c = round(previous_temp + random.uniform(15, 25), 2)
        humidity = round(random.choice([random.uniform(5, 15), random.uniform(85, 99)]), 2)
        object_temp = round(temp_c + random.uniform(18, 30), 2)
        reason = "Fake abnormal sensor values were injected into the system"

    elif attack_type == "Man-in-the-Middle Observation":
        temp_c = round(previous_temp, 2)
        humidity = round(previous_humidity, 2)
        object_temp = round(previous_temp, 2)
        reason = "Network traffic was observed without directly changing the sensor reading"

    elif attack_type == "Replay Attack":
        temp_c = previous_temp
        humidity = previous_humidity
        object_temp = previous_temp
        reason = "Old valid readings were resent to hide the real current state"

    elif attack_type == "DDoS / Flooding Attempt":
        temp_c = round(previous_temp + random.uniform(-2, 2), 2)
        humidity = round(previous_humidity + random.uniform(-3, 3), 2)
        object_temp = round(temp_c, 2)
        reason = "High-frequency fake requests attempted to overwhelm the monitoring API"

    elif attack_type == "Malware Data Manipulation":
        temp_c = round(random.uniform(0, 50), 2)
        humidity = round(random.uniform(0, 100), 2)
        object_temp = round(random.uniform(-10, 60), 2)
        reason = "Gateway-side malware manipulated sensor values before submission"

    else:
        temp_c = round(previous_temp + random.uniform(10, 20), 2)
        humidity = round(previous_humidity, 2)
        object_temp = round(temp_c + random.uniform(15, 25), 2)
        reason = "An unauthorized fake device attempted to impersonate the real ESP32 sensor"

    temp_fh = round((temp_c * 9 / 5) + 32, 2)

    return {
        "attack_type": attack_type,
        "attack_reason": reason,
        "behavior": {
            "serial_reading": random.randint(100, 5000),
            "temp_c": temp_c,
            "temp_fh": temp_fh,
            "humidity": humidity,
            "object_temp": object_temp,
            "nw_cooling": random.choice([0, 1])
        }
    }


@app.route("/")
def welcome():
    return render_template("welcome.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").lower().strip()
        password = request.form.get("password", "")

        if username == "doctor" and password == "123":
            session["role"] = "doctor"
            session["username"] = "doctor"
            return redirect(url_for("clinical_dashboard"))

        if username == "soc" and password == "123":
            session["role"] = "soc"
            session["username"] = "soc"
            return redirect(url_for("soc_dashboard"))

        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("welcome"))


@app.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect(url_for("login"))

    if session.get("role") == "doctor":
        return redirect(url_for("clinical_dashboard"))

    return redirect(url_for("soc_dashboard"))


@app.route("/clinical")
def clinical_dashboard():
    if not require_login("doctor"):
        return redirect(url_for("login"))

    devices = load_devices()
    devices = check_sensor_availability(devices)
    stats = get_dashboard_stats(devices)

    return render_template("clinical_dashboard.html", devices=devices, stats=stats)


@app.route("/soc")
def soc_dashboard():
    if not require_login("soc"):
        return redirect(url_for("login"))

    devices = load_devices()
    devices = check_sensor_availability(devices)
    devices = refresh_security_event_state(devices)
    save_devices(devices)

    vulnerability_risks = get_vulnerability_risks(devices)
    vulnerability_percentage = get_vulnerability_percentage(vulnerability_risks)
    stats = get_dashboard_stats(devices)
    stats["cyber_risk"] = vulnerability_percentage

    return render_template(
        "soc_dashboard.html",
        devices=devices,
        vulnerability_risks=vulnerability_risks,
        vulnerability_percentage=vulnerability_percentage,
        stats=stats
    )


@app.route("/api/clinical_live")
def clinical_live_data():
    if not require_login("doctor"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    devices = load_devices()
    devices = check_sensor_availability(devices)
    stats = get_dashboard_stats(devices)

    return jsonify({
        "success": True,
        "devices": devices,
        "stats": stats
    })


@app.route("/api/soc_live")
def soc_live_data():
    if not require_login("soc"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    devices = load_devices()
    devices = check_sensor_availability(devices)
    devices = refresh_security_event_state(devices)
    save_devices(devices)

    vulnerability_risks = get_vulnerability_risks(devices)
    vulnerability_percentage = get_vulnerability_percentage(vulnerability_risks)

    stats = get_dashboard_stats(devices)
    stats["cyber_risk"] = vulnerability_percentage

    return jsonify({
        "success": True,
        "devices": devices,
        "stats": stats,
        "vulnerability_risks": vulnerability_risks,
        "vulnerability_percentage": vulnerability_percentage
    })


if DEV_MODE:
    @app.route("/simulate_attack/<int:device_index>")
    def simulate_attack(device_index):
        if not require_login("soc"):
            return redirect(url_for("login"))

        devices = load_devices()

        if device_index < 0 or device_index >= len(devices):
            return redirect(url_for("soc_dashboard"))

        attack = generate_attack_reading(devices[device_index])

        process_device_reading(
            device_index,
            attack["behavior"],
            simulated_attack=True,
            attack_type=attack["attack_type"],
            attack_reason=attack["attack_reason"]
        )

        return redirect(url_for("soc_dashboard"))


@app.route("/soc/isolate/<int:device_index>")
def isolate_device(device_index):
    if not require_login("soc"):
        return redirect(url_for("login"))

    devices = load_devices()

    if 0 <= device_index < len(devices):
        devices[device_index]["isolation_status"] = "Isolated"
        devices[device_index]["security_status"] = "Isolated"
        devices[device_index]["action"] = "Sensor Isolated by SOC"
        devices[device_index]["attack_status"] = "Possible Cyber Attack"

    save_devices(devices)

    return redirect(url_for("soc_dashboard"))


@app.route("/soc/restore/<int:device_index>")
def restore_device(device_index):
    if not require_login("soc"):
        return redirect(url_for("login"))

    devices = load_devices()

    if 0 <= device_index < len(devices):
        devices[device_index]["isolation_status"] = "Active"
        devices[device_index]["security_status"] = "Secure"
        devices[device_index]["attack_status"] = "Normal Operation"
        devices[device_index]["anomaly_status"] = "Normal Pattern"
        devices[device_index]["behavior_status"] = "Normal Behavior"
        devices[device_index]["behavior_reason"] = "Sensor restored after SOC validation"
        devices[device_index]["attack_type"] = "-"
        devices[device_index]["attack_reason"] = "-"
        devices[device_index]["action"] = "Sensor Restored by SOC"
        devices[device_index]["risk_score"] = 0
        devices[device_index]["risk_level"] = "Low"
        devices[device_index]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    save_devices(devices)

    return redirect(url_for("soc_dashboard"))


@app.route("/api/sensor_reading", methods=["POST"])
def api_sensor_reading():
    data = request.get_json(silent=True)

    if not data:
        trigger_external_attack(
            0,
            "Malformed JSON",
            "A request reached the sensor API without valid JSON data",
            sensor_id=None,
            temperature=None,
            humidity=None,
            http_code=400
        )
        return jsonify({
            "success": False,
            "message": "Invalid JSON payload",
            "attack_detected": True
        }), 400

    device_index = int(data.get("device_index", 0))

    # Require HMAC authentication fields
    required_fields = ["sensor_id", "temperature", "humidity", "timestamp", "nonce", "signature"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        trigger_external_attack(
            device_index,
            "Missing HMAC Signature",
            f"Missing fields: {', '.join(missing)}",
            sensor_id=sensor_id if 'sensor_id' in data else None,
            temperature=data.get('temperature'),
            humidity=data.get('humidity'),
            http_code=400
        )
        return jsonify({"success": False, "message": f"Missing fields: {', '.join(missing)}", "attack_detected": True}), 400

    sensor_id = data.get("sensor_id", "")

    # Optionally verify sensor identity is known
    if sensor_id != TRUSTED_SENSOR_ID:
        trigger_external_attack(
            device_index,
            "Unknown Sensor ID",
            "A device attempted to submit sensor readings with an unknown sensor_id",
            sensor_id=sensor_id,
            temperature=data.get('temperature'),
            humidity=data.get('humidity'),
            http_code=401
        )
        return jsonify({"success": False, "message": "Unauthorized sensor_id", "attack_detected": True, "attack_type": "Unknown Sensor ID"}), 401

    # Read and validate numeric fields
    try:
        temp_c = float(data.get("temperature"))
        humidity = float(data.get("humidity"))
        ts = int(data.get("timestamp"))
    except Exception:
        trigger_external_attack(
            device_index,
            "Invalid Payload",
            "A request sent non-numeric temperature, humidity, or timestamp values",
            sensor_id=sensor_id,
            temperature=data.get('temperature'),
            humidity=data.get('humidity'),
            http_code=400
        )
        return jsonify({"success": False, "message": "Temperature, humidity, and timestamp must be numeric", "attack_detected": True, "attack_type": "Invalid Payload"}), 400

    nonce = str(data.get("nonce"))
    signature = str(data.get("signature"))

    # Replay protection: reject timestamps older than 60s
    now = int(time.time())
    if abs(now - ts) > 60:
        print("Old timestamp rejected", ts, "now", now)
        trigger_external_attack(
            device_index,
            "Old Timestamp",
            "Rejected sensor reading due to old timestamp",
            sensor_id=sensor_id,
            temperature=temp_c,
            humidity=humidity,
            http_code=401
        )
        return jsonify({"success": False, "message": "Old timestamp rejected", "attack_detected": True, "attack_type": "Old Timestamp"}), 401

    # Replay protection: reject reused nonce
    if nonce_exists(sensor_id, nonce):
        print("Replay nonce rejected for sensor", sensor_id, nonce)
        trigger_external_attack(
            device_index,
            "Replay Nonce",
            "Rejected sensor reading due to reused nonce",
            sensor_id=sensor_id,
            temperature=temp_c,
            humidity=humidity,
            http_code=401
        )
        return jsonify({"success": False, "message": "Replay nonce rejected", "attack_detected": True, "attack_type": "Replay Nonce"}), 401

    # Compute expected HMAC-SHA-256 signature; message format must be exact
    # sensor_id|temperature|humidity|timestamp|nonce with temperature/humidity formatted to two decimals
    msg = f"{sensor_id}|{format(temp_c, '.2f')}|{format(humidity, '.2f')}|{int(ts)}|{nonce}"
    expected_sig = hmac.new(SHARED_SECRET.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        print("Invalid HMAC signature rejected", "expected", expected_sig, "received", signature)
        trigger_external_attack(
            device_index,
            "Invalid HMAC Signature",
            "Rejected sensor reading due to invalid HMAC signature",
            sensor_id=sensor_id,
            temperature=temp_c,
            humidity=humidity,
            http_code=401
        )
        return jsonify({"success": False, "message": "Invalid sensor signature", "attack_detected": True, "attack_type": "Invalid HMAC Signature"}), 401

    # Signature valid — store nonce and proceed
    print("Valid HMAC reading accepted for sensor", sensor_id)
    store_nonce(sensor_id, nonce, ts)
    record_security_event(
        "Valid ESP32 HMAC Reading",
        sensor_id=sensor_id,
        temperature=temp_c,
        humidity=humidity,
        risk_score=0,
        risk_level="Low",
        recommended_action="Continue monitoring and maintain secure sensor authentication",
        http_code=200
    )

    device = load_devices()[device_index]
    device["last_valid_reading_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    device["last_security_event_time"] = ""
    device["attack_status"] = "Normal Operation"
    device["security_status"] = "Secure"
    device["attack_type"] = "-"
    device["attack_reason"] = "-"
    save_devices(load_devices())

    if temp_c < -10 or temp_c > 80 or humidity < 0 or humidity > 100:
        trigger_external_attack(
            device_index,
            "Invalid Payload",
            "A request submitted physically impossible temperature or humidity values",
            sensor_id=sensor_id,
            temperature=temp_c,
            humidity=humidity,
            http_code=400
        )

        return jsonify({
            "success": False,
            "message": "Impossible sensor values detected",
            "attack_detected": True,
            "attack_type": "Invalid Payload"
        }), 400

    temp_fh = round((temp_c * 9 / 5) + 32, 2)

    behavior = {
        "serial_reading": random.randint(100, 5000),
        "temp_c": round(temp_c, 2),
        "temp_fh": temp_fh,
        "humidity": round(humidity, 2),
        "object_temp": round(temp_c, 2),
        "nw_cooling": 0
    }

    success = process_device_reading(device_index, behavior, simulated_attack=False)

    if not success:
        return jsonify({
            "success": False,
            "message": "Invalid or isolated device"
        }), 400

    devices = load_devices()
    device = devices[device_index]
    device["last_valid_reading_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    device["last_security_event_time"] = ""
    device["attack_status"] = "Normal Operation"
    device["security_status"] = "Secure"
    save_devices(devices)

    return jsonify({
        "success": True,
        "temperature": device["temperature_c"],
        "humidity": device["humidity"],
        "status": device["status"],
        "risk_score": device["risk_score"],
        "environment_reason": device["environment_reason"],
        "attack_status": device["attack_status"],
        "security_status": device["security_status"],
        "behavior_status": device["behavior_status"],
        "behavior_reason": device["behavior_reason"],
        "attack_type": device["attack_type"],
        "attack_reason": device["attack_reason"]
    })


@app.route("/logs")
def logs():
    if not require_login():
        return redirect(url_for("login"))

    logs_data = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            reader = csv.DictReader(file)
            logs_data = list(reader)

    return render_template("logs.html", logs=logs_data)


@app.route("/verify_logs")
def verify_logs():
    if not require_login():
        return redirect(url_for("login"))

    is_valid, checked, first_tampered = verify_secure_logs()
    status = "Valid" if is_valid else "Tampered"
    verification_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hash_algorithm = "SHA-256"
    chain_type = "Previous-hash linked audit trail"
    recent_incidents = get_recent_tamper_incidents(limit=10)

    return render_template(
        "verify_logs.html",
        status=status,
        checked=checked,
        first_tampered=first_tampered,
        verification_time=verification_time,
        hash_algorithm=hash_algorithm,
        chain_type=chain_type,
        recent_incidents=recent_incidents
    )


if __name__ == "__main__":
    ensure_single_sensor()
    app.run(host="0.0.0.0", port=5000, debug=True)