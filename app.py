from flask import Flask, render_template, redirect, request, url_for, session
import joblib
import csv
import os
import random
from datetime import datetime

app = Flask(__name__)
app.secret_key = "mediguard_demo_secret_key"

condition_model = joblib.load("condition_model.pkl")
anomaly_model = joblib.load("anomaly_model.pkl")
attack_model = joblib.load("attack_model.pkl")

DEVICES_FILE = "data/devices.csv"
LOG_FILE = "logs.csv"


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
        "last_temperature", "last_humidity", "repeat_count"
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
        "repeat_count": 0
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
                "repeat_count": int(row.get("repeat_count") or 0)
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


def get_dashboard_stats(devices):
    total = len(devices)
    normal = sum(1 for d in devices if d.get("status") == "Normal")
    warning = sum(1 for d in devices if d.get("status") == "Warning")
    critical = sum(1 for d in devices if d.get("status") == "Critical")
    anomalies = sum(1 for d in devices if d.get("anomaly_status") == "Anomalous")
    attacks = sum(1 for d in devices if d.get("attack_status") == "Possible Cyber Attack")
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
    temp = behavior["temp_c"]
    humidity = behavior["humidity"]

    risk_score = 0
    reasons = []

    if 20 <= temp <= 30:
        risk_score += 10
        reasons.append("Temperature is within normal room range")
    elif 30 < temp < 38:
        risk_score += 45
        reasons.append("Temperature is above normal room range")
    elif temp >= 38:
        risk_score += 75
        reasons.append("Temperature is critically high")
    elif 15 <= temp < 20:
        risk_score += 35
        reasons.append("Temperature is lower than normal room range")
    else:
        risk_score += 60
        reasons.append("Temperature is critically abnormal")

    if 30 <= humidity <= 70:
        risk_score += 5
        reasons.append("Humidity is within normal room range")
    elif 20 <= humidity < 30:
        risk_score += 20
        reasons.append("Humidity is lower than normal")
    elif 70 < humidity <= 80:
        risk_score += 20
        reasons.append("Humidity is higher than normal")
    elif humidity < 20:
        risk_score += 40
        reasons.append("Humidity is critically low")
    else:
        risk_score += 40
        reasons.append("Humidity is critically high")

    if ml_prediction == 1:
        risk_score += 5
        reasons.append("Condition model detected risky reading")

    if anomaly_flag == 1:
        risk_score += 5
        reasons.append("Suspicious data behavior detected")

    risk_score = min(risk_score, 100)
    reason_text = "; ".join(reasons)

    if temp >= 38 or humidity < 20 or humidity > 80 or risk_score >= 70:
        return "Critical", "High", "Immediate Environmental Check Required", risk_score, reason_text
    elif temp > 30 or temp < 20 or humidity < 30 or humidity > 70 or risk_score >= 30:
        return "Warning", "Medium", "Check Room Conditions", risk_score, reason_text
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
    return int(condition_model.predict(make_features(behavior))[0])


def get_anomaly_status(behavior):
    prediction = anomaly_model.predict(make_features(behavior))[0]
    if prediction == -1:
        return "Anomalous", 1
    return "Normal Pattern", 0


def get_attack_model_decision(environmental_risk, vulnerability_score, anomaly_flag, ml_prediction):
    features = [[environmental_risk, vulnerability_score, anomaly_flag, ml_prediction]]
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
        if temp_jump >= 20:
            suspicious = True
            reasons.append("Impossible sudden temperature jump")

    if last_humidity is not None:
        humidity_jump = abs(current_humidity - last_humidity)
        if humidity_jump >= 55:
            suspicious = True
            reasons.append("Impossible sudden humidity jump")

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
    active_attack_type = "-"
    has_attack = False
    has_suspicious = False
    has_isolated = False

    for device in devices:
        if device.get("attack_status") == "Possible Cyber Attack":
            has_attack = True
            active_attack_type = device.get("attack_type") or "-"

        if device.get("anomaly_status") == "Anomalous" or device.get("behavior_status") == "Suspicious Behavior":
            has_suspicious = True

        if device.get("isolation_status") == "Isolated":
            has_isolated = True

    vulnerabilities = [
        {
            "id": "V1",
            "vulnerability": "No device authentication",
            "threat": "Fake ESP32/sensor may send false readings",
            "recommendation": "Use API token or device secret for each sensor"
        },
        {
            "id": "V2",
            "vulnerability": "Unencrypted communication",
            "threat": "Traffic may be observed on the network",
            "recommendation": "Use HTTPS/TLS or MQTT over TLS"
        },
        {
            "id": "V3",
            "vulnerability": "No message integrity check",
            "threat": "Sensor data may be changed in transit",
            "recommendation": "Add HMAC/signature for every reading"
        },
        {
            "id": "V4",
            "vulnerability": "No replay protection",
            "threat": "Old valid readings may be resent",
            "recommendation": "Add timestamp, nonce, and last-seen validation"
        },
        {
            "id": "V5",
            "vulnerability": "No input validation",
            "threat": "Impossible values can affect decisions",
            "recommendation": "Validate ranges, sensor ID, and payload format"
        },
        {
            "id": "V6",
            "vulnerability": "No malware protection on gateway",
            "threat": "Malware on the gateway/laptop may manipulate sensor data",
            "recommendation": "Add endpoint protection and restrict execution permissions"
        },
        {
            "id": "V7",
            "vulnerability": "No rate limiting",
            "threat": "Flooding may overwhelm the API with fake readings",
            "recommendation": "Add rate limiting and request throttling"
        },
        {
            "id": "V8",
            "vulnerability": "No SOC isolation response",
            "threat": "Compromised sensor may remain trusted",
            "recommendation": "Allow SOC to isolate suspicious sensors"
        },
        {
            "id": "V9",
            "vulnerability": "Isolated sensor detected",
            "threat": "Sensor removed from trusted monitoring",
            "recommendation": "Inspect and restore only after validation"
        }
    ]

    normal_scores = {
        "V1": (2, 3),
        "V2": (2, 2),
        "V3": (2, 3),
        "V4": (2, 2),
        "V5": (2, 3),
        "V6": (2, 3),
        "V7": (2, 2),
        "V8": (1, 3),
        "V9": (1, 2),
    }

    suspicious_scores = {
        "V1": (3, 3),
        "V2": (2, 2),
        "V3": (3, 3),
        "V4": (3, 3),
        "V5": (3, 4),
        "V6": (3, 3),
        "V7": (3, 3),
        "V8": (3, 4),
        "V9": (1, 2),
    }

    isolated_scores = {
        "V1": (2, 2),
        "V2": (1, 2),
        "V3": (2, 2),
        "V4": (2, 2),
        "V5": (2, 2),
        "V6": (2, 2),
        "V7": (1, 2),
        "V8": (2, 3),
        "V9": (4, 4),
    }

    attack_profiles = {
        "Data Spoofing Attack": {
            "related": ["V1", "V3", "V5"],
            "scores": {
                "V1": (5, 5),
                "V2": (2, 2),
                "V3": (4, 5),
                "V4": (2, 2),
                "V5": (5, 4),
                "V6": (2, 3),
                "V7": (2, 2),
                "V8": (4, 4),
                "V9": (1, 2),
            }
        },
        "Man-in-the-Middle Observation": {
            "related": ["V2"],
            "scores": {
                "V1": (2, 3),
                "V2": (4, 2),
                "V3": (2, 3),
                "V4": (2, 2),
                "V5": (2, 3),
                "V6": (2, 3),
                "V7": (2, 2),
                "V8": (3, 3),
                "V9": (1, 2),
            }
        },
        "Man-in-the-Middle Modification": {
            "related": ["V2", "V3"],
            "scores": {
                "V1": (3, 3),
                "V2": (5, 4),
                "V3": (5, 5),
                "V4": (3, 3),
                "V5": (3, 3),
                "V6": (2, 3),
                "V7": (2, 2),
                "V8": (4, 4),
                "V9": (1, 2),
            }
        },
        "Replay Attack": {
            "related": ["V4"],
            "scores": {
                "V1": (3, 3),
                "V2": (2, 2),
                "V3": (3, 3),
                "V4": (5, 5),
                "V5": (2, 3),
                "V6": (2, 3),
                "V7": (2, 2),
                "V8": (4, 4),
                "V9": (1, 2),
            }
        },
        "DDoS / Flooding Attempt": {
            "related": ["V7"],
            "scores": {
                "V1": (2, 2),
                "V2": (1, 2),
                "V3": (2, 2),
                "V4": (2, 2),
                "V5": (3, 3),
                "V6": (2, 2),
                "V7": (5, 5),
                "V8": (4, 4),
                "V9": (1, 2),
            }
        },
        "Malware Data Manipulation": {
            "related": ["V6", "V3", "V5"],
            "scores": {
                "V1": (3, 3),
                "V2": (2, 2),
                "V3": (4, 5),
                "V4": (2, 2),
                "V5": (4, 4),
                "V6": (5, 5),
                "V7": (2, 2),
                "V8": (4, 4),
                "V9": (1, 2),
            }
        },
        "Sensor Identity Spoofing": {
            "related": ["V1"],
            "scores": {
                "V1": (5, 5),
                "V2": (2, 2),
                "V3": (3, 4),
                "V4": (3, 3),
                "V5": (4, 4),
                "V6": (2, 3),
                "V7": (2, 2),
                "V8": (4, 4),
                "V9": (1, 2),
            }
        },
        "Unauthorized Sensor Spoofing": {
            "related": ["V1"],
            "scores": {
                "V1": (5, 5),
                "V2": (2, 2),
                "V3": (3, 4),
                "V4": (2, 2),
                "V5": (4, 4),
                "V6": (2, 3),
                "V7": (2, 2),
                "V8": (4, 4),
                "V9": (1, 2),
            }
        },
        "Impossible Sensor Payload": {
            "related": ["V5"],
            "scores": {
                "V1": (3, 3),
                "V2": (1, 2),
                "V3": (2, 3),
                "V4": (2, 2),
                "V5": (5, 5),
                "V6": (2, 3),
                "V7": (2, 2),
                "V8": (4, 4),
                "V9": (1, 2),
            }
        },
    }

    if has_attack:
        profile = attack_profiles.get(active_attack_type)
        if profile is None:
            profile = {
                "related": ["V1", "V3", "V5"],
                "scores": suspicious_scores
            }

        selected_scores = profile["scores"]
        related_ids = set(profile["related"])
        matrix_mode = "attack"

    elif has_isolated:
        selected_scores = isolated_scores
        related_ids = {"V9"}
        matrix_mode = "isolated"

    elif has_suspicious:
        selected_scores = suspicious_scores
        related_ids = {"V5", "V8"}
        matrix_mode = "suspicious"

    else:
        selected_scores = normal_scores
        related_ids = set()
        matrix_mode = "normal"

    for item in vulnerabilities:
        likelihood, impact = selected_scores.get(item["id"], (2, 2))
        score = likelihood * impact

        item["likelihood"] = likelihood
        item["impact"] = impact
        item["score"] = score
        item["related"] = item["id"] in related_ids
        item["matrix_mode"] = matrix_mode
        item["active_attack_type"] = active_attack_type

        if score <= 4:
            item["risk_level"] = "Low"
        elif score <= 9:
            item["risk_level"] = "Medium"
        elif score <= 16:
            item["risk_level"] = "High"
        else:
            item["risk_level"] = "Critical"

    return vulnerabilities


def get_vulnerability_percentage(vulnerability_risks):
    if not vulnerability_risks:
        return 0

    related = [risk for risk in vulnerability_risks if risk.get("related")]

    if related:
        related_scores = [risk["score"] for risk in related]
        max_related_score = max(related_scores)
        avg_related_score = sum(related_scores) / len(related_scores)
        weighted_score = (0.70 * max_related_score) + (0.30 * avg_related_score)
    else:
        all_scores = [risk["score"] for risk in vulnerability_risks]
        weighted_score = sum(all_scores) / len(all_scores)

    return min(100, round((weighted_score / 25) * 100))


def get_security_status(attack_status, anomaly_status, isolation_status):
    if isolation_status == "Isolated":
        return "Isolated"
    if attack_status == "Possible Cyber Attack":
        return "Under Attack"
    if anomaly_status == "Anomalous":
        return "Suspicious"
    return "Secure"


def save_log(device, behavior, ml_prediction, anomaly_status, risk_score, risk_level, action, attack_status):
    file_exists = os.path.exists(LOG_FILE)

    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "time", "device_name", "device_type", "location",
                "temperature_c", "humidity", "object_temperature",
                "ml_prediction", "anomaly_status", "risk_score",
                "risk_level", "action", "attack_status"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            device["device_name"],
            device["device_type"],
            device["location"],
            behavior["temp_c"],
            behavior["humidity"],
            behavior["object_temp"],
            ml_prediction,
            anomaly_status,
            risk_score,
            risk_level,
            action,
            attack_status
        ])


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

    status, risk_level, action, risk_score, environment_reason = calculate_environmental_result(
        behavior,
        ml_prediction,
        anomaly_flag
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
        risk_score,
        vulnerability_percentage,
        anomaly_flag,
        ml_prediction
    )

    if simulated_attack:
        attack_status = "Possible Cyber Attack"
    elif already_under_attack:
        attack_status = "Possible Cyber Attack"
    elif status == "Critical":
        attack_status = "Environmental Failure"
    elif status == "Warning":
        attack_status = "Environmental Warning"
    else:
        attack_status = "Normal Operation"

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

        if final_risk_score >= 80:
            final_risk_level = "Critical"
        elif final_risk_score >= 60:
            final_risk_level = "High"
        elif final_risk_score >= 30:
            final_risk_level = "Medium"
        else:
            final_risk_level = "Low"
    else:
        final_risk_score = risk_score
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
        "repeat_count": repeat_count
    }

    update_device_readings(device_index, updated_data)

    save_log(
        device,
        behavior,
        ml_prediction,
        anomaly_status,
        risk_score,
        risk_level,
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
    stats = get_dashboard_stats(devices)

    return render_template("clinical_dashboard.html", devices=devices, stats=stats)


@app.route("/soc")
def soc_dashboard():
    if not require_login("soc"):
        return redirect(url_for("login"))

    devices = load_devices()
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

    save_devices(devices)

    return redirect(url_for("soc_dashboard"))


@app.route("/api/sensor_reading", methods=["POST"])
def api_sensor_reading():
    data = request.get_json()

    device_index = int(data.get("device_index", 0))
    temp_c = float(data.get("temperature"))
    humidity = float(data.get("humidity"))

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
        return {"success": False, "message": "Invalid or isolated device"}, 400

    devices = load_devices()
    device = devices[device_index]

    return {
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
    }


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


if __name__ == "__main__":
    ensure_single_sensor()
    app.run(host="0.0.0.0", port=5000, debug=True)