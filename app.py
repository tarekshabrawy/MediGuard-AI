"""
app.py - MediGuard AI Hybrid 3-Model System

Includes:
- Welcome page
- Main dashboard
- Add / delete medical storage sensors
- Safe / Warning / Critical simulation
- 3 AI models:
  1. condition_model.pkl
  2. anomaly_model.pkl
  3. attack_model.pkl
- Dynamic cybersecurity vulnerability matrix
- Dashboard statistics
"""

from flask import Flask, render_template, redirect, request, url_for
import joblib
import csv
import os
import random
from datetime import datetime

app = Flask(__name__)

condition_model = joblib.load("condition_model.pkl")
anomaly_model = joblib.load("anomaly_model.pkl")
attack_model = joblib.load("attack_model.pkl")

DEVICES_FILE = "data/devices.csv"
LOG_FILE = "logs.csv"


def load_devices():
    devices = []

    if os.path.exists(DEVICES_FILE):
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
                    "risk_score": int(row.get("risk_score") or 0),
                    "risk_level": row.get("risk_level") or "-",
                    "action": row.get("action") or "-",
                    "ml_prediction": row.get("ml_prediction") or "-",
                    "anomaly_status": row.get("anomaly_status") or "-",
                    "attack_status": row.get("attack_status") or "-"
                })

    return devices


def get_dashboard_stats(devices):
    total = len(devices)
    normal = sum(1 for d in devices if d.get("status") == "Normal")
    warning = sum(1 for d in devices if d.get("status") == "Warning")
    critical = sum(1 for d in devices if d.get("status") == "Critical")
    no_data = sum(1 for d in devices if d.get("status") in ["No Data", "-", ""])

    anomalies = sum(1 for d in devices if d.get("anomaly_status") == "Anomalous")
    attacks = sum(1 for d in devices if d.get("attack_status") == "Possible Cyber Attack")
    failures = sum(1 for d in devices if d.get("attack_status") == "Environmental Failure")

    avg_risk = round(sum(int(d.get("risk_score") or 0) for d in devices) / total, 1) if total > 0 else 0
    active = total - no_data

    return {
        "total": total,
        "active": active,
        "normal": normal,
        "warning": warning,
        "critical": critical,
        "no_data": no_data,
        "anomalies": anomalies,
        "attacks": attacks,
        "failures": failures,
        "avg_risk": avg_risk
    }


def save_device(device_name, device_type, location, storage_type):
    os.makedirs("data", exist_ok=True)
    file_exists = os.path.exists(DEVICES_FILE)

    with open(DEVICES_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "device_name", "device_type", "location", "storage_type",
                "temperature_c", "humidity", "object_temperature", "cooling_status",
                "status", "risk_score", "risk_level", "action",
                "ml_prediction", "anomaly_status", "attack_status"
            ])

        writer.writerow([
            device_name, device_type, location, storage_type,
            "", "", "", "",
            "No Data", 0, "-", "-",
            "-", "-", "-"
        ])


def update_device_readings(device_index, updated_data):
    if not os.path.exists(DEVICES_FILE):
        return

    with open(DEVICES_FILE, "r", newline="") as file:
        devices = list(csv.DictReader(file))

    if device_index < 0 or device_index >= len(devices):
        return

    for key, value in updated_data.items():
        devices[device_index][key] = value

    fieldnames = [
        "device_name", "device_type", "location", "storage_type",
        "temperature_c", "humidity", "object_temperature", "cooling_status",
        "status", "risk_score", "risk_level", "action",
        "ml_prediction", "anomaly_status", "attack_status"
    ]

    with open(DEVICES_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(devices)


def generate_readings(mode):
    if mode == "safe":
        temp_c = round(random.uniform(2.0, 8.0), 2)
        humidity = round(random.uniform(40.0, 60.0), 2)
        object_temp = round(temp_c + random.uniform(-0.3, 0.3), 2)
        cooling = 0

    elif mode == "warning":
        temp_c = round(random.uniform(7.5, 13.0), 2)
        humidity = round(random.uniform(55.0, 78.0), 2)
        object_temp = round(temp_c + random.uniform(-0.4, 1.0), 2)
        cooling = 0

    else:
        temp_c = round(random.uniform(12.0, 28.0), 2)
        humidity = round(random.uniform(70.0, 98.0), 2)
        object_temp = round(temp_c + random.uniform(0.5, 3.0), 2)
        cooling = random.choice([0, 1])

    temp_fh = round((temp_c * 9 / 5) + 32, 2)

    return {
        "serial_reading": random.randint(100, 5000),
        "temp_c": temp_c,
        "temp_fh": temp_fh,
        "humidity": humidity,
        "object_temp": object_temp,
        "nw_cooling": cooling
    }


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


def calculate_environmental_result(behavior, ml_prediction, anomaly_flag):
    risk_score = 0

    temp = behavior["temp_c"]
    humidity = behavior["humidity"]
    object_temp = behavior["object_temp"]
    cooling = behavior["nw_cooling"]

    if temp < 2:
        risk_score += min(20, int((2 - temp) * 5))
    elif 2 <= temp <= 8:
        risk_score += 5
    elif 8 < temp <= 12:
        risk_score += int((temp - 8) * 7)
    elif 12 < temp <= 20:
        risk_score += 35 + int((temp - 12) * 3)
    else:
        risk_score += 60

    if 40 <= humidity <= 60:
        risk_score += 5
    elif 60 < humidity <= 75:
        risk_score += int((humidity - 60) * 1.3)
    elif humidity > 75:
        risk_score += 25 + int((humidity - 75) * 0.8)
    else:
        risk_score += 10

    if abs(object_temp - temp) > 2:
        risk_score += 10

    if cooling == 1:
        risk_score += 20

    if ml_prediction == 1:
        risk_score += 10

    if anomaly_flag == 1:
        risk_score += 10

    risk_score = min(risk_score, 100)

    if risk_score < 30:
        return "Normal", "Low", "Continue Monitoring", risk_score
    elif risk_score < 70:
        return "Warning", "Medium", "Alert Admin", risk_score
    else:
        return "Critical", "High", "Immediate Action Required", risk_score


def get_vulnerability_risks(devices):
    total_devices = len(devices)
    critical_count = 0
    warning_count = 0
    total_risk = 0

    for device in devices:
        status = device.get("status", "")
        risk_score = int(device.get("risk_score") or 0)
        total_risk += risk_score

        if status == "Critical":
            critical_count += 1
        elif status == "Warning":
            warning_count += 1

    avg_risk = (total_risk / total_devices) if total_devices > 0 else 0

    if total_devices == 0:
        base_likelihood = 1
        base_impact = 2
    else:
        severity_ratio = critical_count / total_devices

        if severity_ratio >= 0.6:
            base_likelihood = 5
            base_impact = 5
        elif severity_ratio >= 0.3:
            base_likelihood = 4
            base_impact = 4
        elif warning_count > 0:
            base_likelihood = 3
            base_impact = 3
        elif avg_risk > 30:
            base_likelihood = 2
            base_impact = 3
        else:
            base_likelihood = 2
            base_impact = 2

    vulnerabilities = [
        {
            "id": "V1",
            "vulnerability": "No device authentication",
            "threat": "Fake sensor may send false readings",
            "likelihood": base_likelihood + (1 if critical_count > 0 else 0),
            "impact": base_impact + 1,
            "recommendation": "Add API key or token for every sensor"
        },
        {
            "id": "V2",
            "vulnerability": "Unencrypted communication",
            "threat": "Attacker may read or modify sensor data",
            "likelihood": base_likelihood,
            "impact": base_impact + (1 if avg_risk > 50 else 0),
            "recommendation": "Use HTTPS/TLS or MQTT over TLS"
        },
        {
            "id": "V3",
            "vulnerability": "Weak dashboard login",
            "threat": "Unauthorized user may access the dashboard",
            "likelihood": base_likelihood,
            "impact": base_impact,
            "recommendation": "Add strong login and password hashing"
        },
        {
            "id": "V4",
            "vulnerability": "No input validation",
            "threat": "Fake or invalid readings may affect decisions",
            "likelihood": base_likelihood + (1 if avg_risk > 60 else 0),
            "impact": base_impact + (1 if critical_count > 0 else 0),
            "recommendation": "Validate sensor ranges"
        },
        {
            "id": "V5",
            "vulnerability": "No sensor offline detection",
            "threat": "Old readings may appear live",
            "likelihood": base_likelihood + (1 if warning_count > 0 else 0),
            "impact": base_impact,
            "recommendation": "Add heartbeat mechanism"
        },
        {
            "id": "V6",
            "vulnerability": "No alert confirmation",
            "threat": "Critical alerts may be ignored",
            "likelihood": base_likelihood + (1 if critical_count > 1 else 0),
            "impact": base_impact,
            "recommendation": "Add alert acknowledgement"
        }
    ]

    for item in vulnerabilities:
        item["likelihood"] = min(item["likelihood"], 5)
        item["impact"] = min(item["impact"], 5)

        score = item["likelihood"] * item["impact"]
        item["score"] = score

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
    avg_score = sum(risk["score"] for risk in vulnerability_risks) / len(vulnerability_risks)
    return min(100, int((avg_score / 25) * 100))


def get_attack_model_decision(environmental_risk, vulnerability_score, anomaly_flag, ml_prediction):
    features = [[environmental_risk, vulnerability_score, anomaly_flag, ml_prediction]]
    return attack_model.predict(features)[0]


def final_attack_decision(status, attack_ai_decision, anomaly_flag, vulnerability_score):
    if status == "Normal":
        if anomaly_flag == 1 and vulnerability_score >= 60:
            return "Suspicious Behavior"
        return "Normal Operation"

    if status == "Warning":
        if anomaly_flag == 1 or vulnerability_score >= 60:
            return "Suspicious Behavior"
        return "Environmental Warning"

    if status == "Critical":
        if attack_ai_decision == "Possible Cyber Attack":
            return "Possible Cyber Attack"
        if anomaly_flag == 1 and vulnerability_score >= 50:
            return "Possible Cyber Attack"
        return "Environmental Failure"

    return attack_ai_decision


def save_log(device, behavior, ml_prediction, anomaly_status, risk_score, risk_level, action, attack_status):
    file_exists = os.path.exists(LOG_FILE)

    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "time", "device_name", "device_type", "location", "storage_type",
                "temperature_c", "humidity", "object_temperature", "cooling_status",
                "ml_prediction", "anomaly_status", "risk_score", "risk_level",
                "action", "attack_status"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            device["device_name"],
            device["device_type"],
            device["location"],
            device["storage_type"],
            behavior["temp_c"],
            behavior["humidity"],
            behavior["object_temp"],
            "Normal" if behavior["nw_cooling"] == 0 else "Failure",
            ml_prediction,
            anomaly_status,
            risk_score,
            risk_level,
            action,
            attack_status
        ])


@app.route("/")
def welcome():
    return render_template("welcome.html")


@app.route("/dashboard")
def dashboard():
    devices = load_devices()
    vulnerability_risks = get_vulnerability_risks(devices)
    stats = get_dashboard_stats(devices)

    return render_template(
        "index.html",
        devices=devices,
        vulnerability_risks=vulnerability_risks,
        stats=stats
    )


@app.route("/add_device", methods=["GET", "POST"])
def add_device():
    if request.method == "POST":
        save_device(
            request.form.get("device_name"),
            request.form.get("device_type"),
            request.form.get("location"),
            request.form.get("storage_type")
        )
        return redirect(url_for("dashboard"))

    return render_template("add_device.html")


@app.route("/simulate/<int:device_index>/<mode>")
def simulate(device_index, mode):
    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return redirect(url_for("dashboard"))

    device = devices[device_index]
    behavior = generate_readings(mode)

    ml_prediction = get_condition_prediction(behavior)
    anomaly_status, anomaly_flag = get_anomaly_status(behavior)

    status, risk_level, action, risk_score = calculate_environmental_result(
        behavior,
        ml_prediction,
        anomaly_flag
    )

    temp_devices = devices.copy()
    temp_devices[device_index]["status"] = status
    temp_devices[device_index]["risk_score"] = risk_score
    temp_devices[device_index]["risk_level"] = risk_level

    vulnerability_risks = get_vulnerability_risks(temp_devices)
    vulnerability_percentage = get_vulnerability_percentage(vulnerability_risks)

    attack_ai_decision = get_attack_model_decision(
        risk_score,
        vulnerability_percentage,
        anomaly_flag,
        ml_prediction
    )

    attack_status = final_attack_decision(
        status,
        attack_ai_decision,
        anomaly_flag,
        vulnerability_percentage
    )

    updated_data = {
        "temperature_c": behavior["temp_c"],
        "humidity": behavior["humidity"],
        "object_temperature": behavior["object_temp"],
        "cooling_status": "Normal" if behavior["nw_cooling"] == 0 else "Failure",
        "status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": action,
        "ml_prediction": ml_prediction,
        "anomaly_status": anomaly_status,
        "attack_status": attack_status
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

    return redirect(url_for("dashboard"))


@app.route("/delete_device/<int:device_index>")
def delete_device(device_index):
    devices = []

    if os.path.exists(DEVICES_FILE):
        with open(DEVICES_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)
            devices = list(reader)

    if 0 <= device_index < len(devices):
        devices.pop(device_index)

    fieldnames = [
        "device_name", "device_type", "location", "storage_type",
        "temperature_c", "humidity", "object_temperature", "cooling_status",
        "status", "risk_score", "risk_level", "action",
        "ml_prediction", "anomaly_status", "attack_status"
    ]

    with open(DEVICES_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(devices)

    return redirect(url_for("dashboard"))


@app.route("/logs")
def logs():
    logs_data = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            reader = csv.DictReader(file)
            logs_data = list(reader)

    return render_template("logs.html", logs=logs_data)


if __name__ == "__main__":
    app.run(debug=True)