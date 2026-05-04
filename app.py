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
        "ml_prediction", "anomaly_status", "attack_status",
        "security_status", "isolation_status",
        "behavior_status", "behavior_reason",
        "last_temperature", "last_humidity", "repeat_count"
    ]


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
                    "attack_status": row.get("attack_status") or "-",
                    "security_status": row.get("security_status") or "Secure",
                    "isolation_status": row.get("isolation_status") or "Active",
                    "behavior_status": row.get("behavior_status") or "-",
                    "behavior_reason": row.get("behavior_reason") or "-",
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


def get_dashboard_stats(devices):
    total = len(devices)

    normal = sum(1 for d in devices if d.get("status") == "Normal")
    warning = sum(1 for d in devices if d.get("status") == "Warning")
    critical = sum(1 for d in devices if d.get("status") == "Critical")
    no_data = sum(1 for d in devices if d.get("status") in ["No Data", "-", ""])

    anomalies = sum(1 for d in devices if d.get("anomaly_status") == "Anomalous")
    attacks = sum(1 for d in devices if d.get("attack_status") == "Possible Cyber Attack")
    failures = sum(1 for d in devices if d.get("attack_status") == "Environmental Failure")
    isolated = sum(1 for d in devices if d.get("isolation_status") == "Isolated")

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
        "isolated": isolated,
        "avg_risk": avg_risk
    }


def save_device(device_name, device_type, location, storage_type):
    devices = load_devices()

    devices.append({
        "device_name": device_name,
        "device_type": device_type,
        "location": location,
        "storage_type": storage_type,
        "temperature_c": "",
        "humidity": "",
        "object_temperature": "",
        "cooling_status": "",
        "status": "No Data",
        "risk_score": 0,
        "risk_level": "-",
        "action": "-",
        "ml_prediction": "-",
        "anomaly_status": "-",
        "attack_status": "-",
        "security_status": "Secure",
        "isolation_status": "Active",
        "behavior_status": "-",
        "behavior_reason": "-",
        "last_temperature": "",
        "last_humidity": "",
        "repeat_count": 0
    })

    save_devices(devices)


def update_device_readings(device_index, updated_data):
    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return

    for key, value in updated_data.items():
        devices[device_index][key] = value

    save_devices(devices)


def generate_readings(mode, current_device=None):
    if mode == "random":
     mode = random.choice(["safe", "physical", "attack", "replay"])
    previous_temp = None
    previous_humidity = None

    if current_device:
        try:
            previous_temp = float(current_device.get("temperature_c"))
            previous_humidity = float(current_device.get("humidity"))
        except:
            previous_temp = None
            previous_humidity = None

    if mode == "safe":
        temp_c = round(random.uniform(2.0, 8.0), 2)
        humidity = round(random.uniform(40.0, 60.0), 2)
        object_temp = round(temp_c + random.uniform(-0.3, 0.3), 2)
        cooling = 0

    elif mode == "physical":
        # Physical/environmental failure:
        # temperature increases gradually and object temperature follows it.
        if previous_temp is None:
            temp_c = round(random.uniform(9.0, 13.0), 2)
        else:
            temp_c = round(min(previous_temp + random.uniform(3.0, 6.0), 28.0), 2)

        if previous_humidity is None:
            humidity = round(random.uniform(60.0, 75.0), 2)
        else:
            humidity = round(min(previous_humidity + random.uniform(3.0, 8.0), 95.0), 2)

        object_temp = round(temp_c + random.uniform(-0.5, 0.8), 2)
        cooling = 1

    elif mode == "attack":
        # Cyber attack scenario:
        # suspicious unrealistic jumps and inconsistent object temperature.
        if previous_temp is None:
            temp_c = round(random.uniform(25.0, 35.0), 2)
        else:
            temp_c = round(previous_temp + random.uniform(15.0, 28.0), 2)

        humidity = round(random.choice([
            random.uniform(5.0, 15.0),
            random.uniform(90.0, 99.0)
        ]), 2)

        object_temp = round(random.choice([
            temp_c + random.uniform(12.0, 25.0),
            temp_c - random.uniform(12.0, 25.0)
        ]), 2)

        cooling = random.choice([0, 1])

    elif mode == "replay":
        # Replay attack scenario:
        # repeated identical readings.
        if previous_temp is not None and previous_humidity is not None:
            temp_c = previous_temp
            humidity = previous_humidity
        else:
            temp_c = round(random.uniform(4.0, 7.0), 2)
            humidity = round(random.uniform(45.0, 55.0), 2)

        object_temp = temp_c
        cooling = 0

    else:
        temp_c = round(random.uniform(7.5, 13.0), 2)
        humidity = round(random.uniform(55.0, 78.0), 2)
        object_temp = round(temp_c + random.uniform(-0.4, 1.0), 2)
        cooling = 0

    temp_fh = round((temp_c * 9 / 5) + 32, 2)

    return {
        "serial_reading": random.randint(100, 5000),
        "temp_c": temp_c,
        "temp_fh": temp_fh,
        "humidity": humidity,
        "object_temp": object_temp,
        "nw_cooling": cooling
    }


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

        if temp_jump >= 12:
            suspicious = True
            reasons.append("Sudden unrealistic temperature jump")

    if last_humidity is not None:
        humidity_jump = abs(current_humidity - last_humidity)

        if humidity_jump >= 35:
            suspicious = True
            reasons.append("Sudden unrealistic humidity jump")

    if abs(object_temp - current_temp) >= 10:
        suspicious = True
        reasons.append("Object temperature does not match sensor temperature")

    if last_temp is not None and last_humidity is not None:
        if current_temp == last_temp and current_humidity == last_humidity:
            repeat_count += 1
        else:
            repeat_count = 0

    if repeat_count >= 3:
        suspicious = True
        reasons.append("Repeated identical readings detected")

    if suspicious:
        return "Suspicious Behavior", "; ".join(reasons), 1, repeat_count

    return "Normal Behavior", "Reading pattern is consistent", 0, repeat_count


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

    attack_count = 0
    suspicious_count = 0
    anomaly_count = 0
    isolated_count = 0

    for device in devices:
        attack_status = device.get("attack_status", "")
        anomaly_status = device.get("anomaly_status", "")
        security_status = device.get("security_status", "")
        isolation_status = device.get("isolation_status", "Active")

        if attack_status == "Possible Cyber Attack" or security_status == "Under Attack":
            attack_count += 1

        if attack_status == "Suspicious Behavior" or security_status == "Suspicious":
            suspicious_count += 1

        if anomaly_status == "Anomalous":
            anomaly_count += 1

        if isolation_status == "Isolated":
            isolated_count += 1

    base_likelihood = 1
    base_impact = 2

    if attack_count >= 2:
        base_likelihood = 5
        base_impact = 5
    elif attack_count == 1:
        base_likelihood = 4
        base_impact = 5
    elif anomaly_count >= 2:
        base_likelihood = 4
        base_impact = 4
    elif anomaly_count == 1 or suspicious_count > 0:
        base_likelihood = 3
        base_impact = 4
    elif isolated_count > 0:
        base_likelihood = 2
        base_impact = 3
    else:
        base_likelihood = 1
        base_impact = 2

    vulnerabilities = [
        {
            "id": "V1",
            "vulnerability": "No device authentication",
            "threat": "Fake sensor may send false readings",
            "likelihood": base_likelihood + (1 if attack_count > 0 else 0),
            "impact": base_impact + (1 if attack_count > 0 else 0),
            "recommendation": "Add API key or token for every sensor"
        },
        {
            "id": "V2",
            "vulnerability": "Unencrypted communication",
            "threat": "Man-in-the-middle may modify readings",
            "likelihood": base_likelihood + (1 if attack_count > 0 or anomaly_count > 0 else 0),
            "impact": base_impact + (1 if attack_count > 0 else 0),
            "recommendation": "Use HTTPS/TLS or MQTT over TLS"
        },
        {
            "id": "V3",
            "vulnerability": "Weak dashboard login",
            "threat": "Unauthorized user may access the dashboard",
            "likelihood": 2 if attack_count == 0 else base_likelihood,
            "impact": 3 if attack_count == 0 else base_impact,
            "recommendation": "Add role-based access control and password hashing"
        },
        {
            "id": "V4",
            "vulnerability": "No input validation",
            "threat": "Fake or invalid readings may affect decisions",
            "likelihood": base_likelihood + (1 if anomaly_count > 0 else 0),
            "impact": base_impact + (1 if attack_count > 0 else 0),
            "recommendation": "Validate sensor ranges, IDs, and timestamps"
        },
        {
            "id": "V5",
            "vulnerability": "No sensor offline detection",
            "threat": "Old readings may appear live",
            "likelihood": 2 + (1 if suspicious_count > 0 else 0),
            "impact": 3 + (1 if attack_count > 0 else 0),
            "recommendation": "Add heartbeat mechanism and last-seen timestamp"
        },
        {
            "id": "V6",
            "vulnerability": "No alert confirmation",
            "threat": "Critical alerts may be ignored",
            "likelihood": 2 + (1 if attack_count > 0 else 0),
            "impact": 3 + (1 if attack_count > 0 else 0),
            "recommendation": "Add alert acknowledgement and escalation"
        },
        {
            "id": "V7",
            "vulnerability": "Isolated sensor detected",
            "threat": "Sensor has been removed from trusted monitoring",
            "likelihood": 3 if isolated_count > 0 else 1,
            "impact": 4 if isolated_count > 0 else 2,
            "recommendation": "Inspect isolated devices before restoring"
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


def process_device_reading(device_index, behavior):
    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return False

    if devices[device_index].get("isolation_status") == "Isolated":
        return False

    device = devices[device_index]

    ml_prediction = get_condition_prediction(behavior)

    model_anomaly_status, model_anomaly_flag = get_anomaly_status(behavior)

    behavior_status, behavior_reason, behavior_anomaly_flag, repeat_count = analyze_sensor_behavior(
        device,
        behavior
    )

    anomaly_flag = 1 if model_anomaly_flag == 1 or behavior_anomaly_flag == 1 else 0

    if anomaly_flag == 1:
        anomaly_status = "Anomalous"
    else:
        anomaly_status = "Normal Pattern"

    status, risk_level, action, risk_score = calculate_environmental_result(
        behavior,
        ml_prediction,
        anomaly_flag
    )

    temp_devices = devices.copy()
    temp_devices[device_index]["status"] = status
    temp_devices[device_index]["risk_score"] = risk_score
    temp_devices[device_index]["risk_level"] = risk_level
    temp_devices[device_index]["anomaly_status"] = anomaly_status
    temp_devices[device_index]["behavior_status"] = behavior_status

    vulnerability_risks = get_vulnerability_risks(temp_devices)
    vulnerability_percentage = get_vulnerability_percentage(vulnerability_risks)

    attack_ai_decision = get_attack_model_decision(
        risk_score,
        vulnerability_percentage,
        anomaly_flag,
        ml_prediction
    )

    # Final realistic decision:
    # Anomaly + cyber vulnerability = possible attack.
    # High temp without suspicious behavior = environmental failure.
    if anomaly_flag == 1 and vulnerability_percentage >= 35:
        attack_status = "Possible Cyber Attack"
    elif status == "Critical":
        attack_status = "Environmental Failure"
    elif status == "Warning":
        attack_status = "Environmental Warning"
    else:
        attack_status = "Normal Operation"

    isolation_status = device.get("isolation_status") or "Active"
    security_status = get_security_status(attack_status, anomaly_status, isolation_status)

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
        "attack_status": attack_status,
        "security_status": security_status,
        "isolation_status": isolation_status,
        "behavior_status": behavior_status,
        "behavior_reason": behavior_reason,
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

    return render_template(
        "clinical_dashboard.html",
        devices=devices,
        stats=stats
    )


@app.route("/soc")
def soc_dashboard():
    if not require_login("soc"):
        return redirect(url_for("login"))

    devices = load_devices()
    vulnerability_risks = get_vulnerability_risks(devices)
    stats = get_dashboard_stats(devices)

    return render_template(
        "soc_dashboard.html",
        devices=devices,
        vulnerability_risks=vulnerability_risks,
        stats=stats
    )


@app.route("/add_device", methods=["GET", "POST"])
def add_device():
    if not require_login():
        return redirect(url_for("login"))

    if request.method == "POST":
        save_device(
            request.form.get("device_name"),
            request.form.get("device_type"),
            request.form.get("location"),
            request.form.get("storage_type")
        )

        if session.get("role") == "soc":
            return redirect(url_for("soc_dashboard"))

        return redirect(url_for("clinical_dashboard"))

    return render_template("add_device.html")


@app.route("/simulate/<int:device_index>/<mode>")
def simulate(device_index, mode):
    if not require_login("soc"):
        return redirect(url_for("login"))

    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return redirect(url_for("soc_dashboard"))

    behavior = generate_readings(mode, devices[device_index])
    process_device_reading(device_index, behavior)

    return redirect(url_for("soc_dashboard"))


@app.route("/delete_device/<int:device_index>")
def delete_device(device_index):
    if not require_login("soc"):
        return redirect(url_for("login"))

    devices = load_devices()

    if 0 <= device_index < len(devices):
        devices.pop(device_index)

    save_devices(devices)

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

    success = process_device_reading(device_index, behavior)

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
        "attack_status": device["attack_status"],
        "security_status": device["security_status"],
        "behavior_status": device["behavior_status"],
        "behavior_reason": device["behavior_reason"]
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
    app.run(host="0.0.0.0", port=5000, debug=True)