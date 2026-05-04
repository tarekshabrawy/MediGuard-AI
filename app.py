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
        reader = csv.DictReader(file)
        devices = list(reader)

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
    """
    Room monitoring logic.

    Temperature:
    Normal   = 20°C to 30°C
    Warning  = 30°C to 37.9°C
    Critical = 38°C+

    Humidity:
    Normal   = 30% to 70%
    Warning  = 20% to 29% OR 71% to 80%
    Critical = below 20% OR above 80%
    """

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

    # Real DHT readings can repeat naturally. Repetition alone is NOT a cyber attack.
    if last_temp is not None:
        temp_jump = abs(current_temp - last_temp)
        if temp_jump >= 18:
            suspicious = True
            reasons.append("Very large sudden temperature jump")

    if last_humidity is not None:
        humidity_jump = abs(current_humidity - last_humidity)
        if humidity_jump >= 50:
            suspicious = True
            reasons.append("Very large sudden humidity jump")

    if abs(object_temp - current_temp) >= 15:
        suspicious = True
        reasons.append("Impossible sensor/object temperature mismatch")

    if last_temp is not None and last_humidity is not None:
        if current_temp == last_temp and current_humidity == last_humidity:
            repeat_count += 1
        else:
            repeat_count = 0

    if suspicious:
        return "Suspicious Behavior", "; ".join(reasons), 1, repeat_count

    return "Normal Behavior", "Real sensor pattern is normal", 0, repeat_count


def get_vulnerability_risks(devices):
    attack_count = 0
    anomaly_count = 0
    isolated_count = 0
    suspicious_count = 0

    for device in devices:
        if device.get("attack_status") == "Possible Cyber Attack":
            attack_count += 1

        if device.get("anomaly_status") == "Anomalous":
            anomaly_count += 1

        if device.get("behavior_status") == "Suspicious Behavior":
            suspicious_count += 1

        if device.get("isolation_status") == "Isolated":
            isolated_count += 1

    if attack_count > 0:
        mode = "attack"
    elif anomaly_count > 0 or suspicious_count > 0:
        mode = "suspicious"
    elif isolated_count > 0:
        mode = "isolated"
    else:
        mode = "normal"

    def values(normal, suspicious, attack, isolated=None):
        if mode == "attack":
            return attack
        if mode == "suspicious":
            return suspicious
        if mode == "isolated" and isolated:
            return isolated
        return normal

    vulnerabilities = [
        {
            "id": "V1",
            "vulnerability": "No device authentication",
            "threat": "Fake ESP32/sensor may send false readings",
            "likelihood": values(2, 4, 5),
            "impact": values(4, 5, 5),
            "recommendation": "Use API token or device secret for each sensor"
        },
        {
            "id": "V2",
            "vulnerability": "Unencrypted communication",
            "threat": "Man-in-the-middle may modify readings",
            "likelihood": values(2, 4, 5),
            "impact": values(4, 5, 5),
            "recommendation": "Use HTTPS/TLS or MQTT over TLS"
        },
        {
            "id": "V3",
            "vulnerability": "No message integrity check",
            "threat": "Sensor data may be changed in transit",
            "likelihood": values(2, 4, 5),
            "impact": values(4, 5, 5),
            "recommendation": "Add HMAC/signature for every reading"
        },
        {
            "id": "V4",
            "vulnerability": "No replay protection",
            "threat": "Old valid readings may be resent",
            "likelihood": values(2, 3, 5),
            "impact": values(3, 4, 5),
            "recommendation": "Add timestamp, nonce, and last-seen validation"
        },
        {
            "id": "V5",
            "vulnerability": "No input validation",
            "threat": "Impossible values can affect decisions",
            "likelihood": values(2, 4, 5),
            "impact": values(3, 4, 5),
            "recommendation": "Validate ranges, sensor ID, and payload format"
        },
        {
            "id": "V6",
            "vulnerability": "No SOC isolation response",
            "threat": "Compromised sensor may remain trusted",
            "likelihood": values(1, 3, 5),
            "impact": values(3, 4, 5),
            "recommendation": "Allow SOC to isolate suspicious sensors"
        },
        {
            "id": "V7",
            "vulnerability": "Isolated sensor detected",
            "threat": "Sensor removed from trusted monitoring",
            "likelihood": values(1, 1, 2, isolated=3),
            "impact": values(2, 2, 3, isolated=4),
            "recommendation": "Inspect and restore only after validation"
        }
    ]

    for item in vulnerabilities:
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


def process_device_reading(device_index, behavior, simulated_attack=False):
    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return False

    if devices[device_index].get("isolation_status") == "Isolated":
        return False

    device = devices[device_index]

    ml_prediction = get_condition_prediction(behavior)

    # We still call the model, but final anomaly decision is based on behavior or SOC attack simulation.
    model_anomaly_status, model_anomaly_flag = get_anomaly_status(behavior)

    behavior_status, behavior_reason, behavior_anomaly_flag, repeat_count = analyze_sensor_behavior(device, behavior)

    if simulated_attack:
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

    temp_devices = devices.copy()
    temp_devices[device_index]["anomaly_status"] = anomaly_status
    temp_devices[device_index]["behavior_status"] = "Suspicious Behavior" if simulated_attack else behavior_status

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
    elif anomaly_flag == 1 and vulnerability_percentage >= 60:
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
        "environment_reason": environment_reason,
        "ml_prediction": ml_prediction,
        "anomaly_status": anomaly_status,
        "attack_status": attack_status,
        "security_status": security_status,
        "isolation_status": isolation_status,
        "behavior_status": "Suspicious Behavior" if simulated_attack else behavior_status,
        "behavior_reason": "Controlled SOC cyber-attack simulation" if simulated_attack else behavior_reason,
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

    attack_type = random.choice(["spoofing", "mitm_modification", "replay_like"])

    if attack_type == "spoofing":
        temp_c = round(previous_temp + random.uniform(12, 25), 2)
        humidity = round(random.choice([random.uniform(5, 15), random.uniform(85, 99)]), 2)
        object_temp = round(temp_c + random.uniform(12, 25), 2)

    elif attack_type == "mitm_modification":
        temp_c = round(random.uniform(-5, 5), 2)
        humidity = round(random.uniform(90, 99), 2)
        object_temp = round(random.uniform(35, 50), 2)

    else:
        temp_c = previous_temp
        humidity = previous_humidity
        object_temp = previous_temp

    temp_fh = round((temp_c * 9 / 5) + 32, 2)

    return {
        "serial_reading": random.randint(100, 5000),
        "temp_c": temp_c,
        "temp_fh": temp_fh,
        "humidity": humidity,
        "object_temp": object_temp,
        "nw_cooling": random.choice([0, 1])
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
    stats = get_dashboard_stats(devices)

    return render_template(
        "soc_dashboard.html",
        devices=devices,
        vulnerability_risks=vulnerability_risks,
        stats=stats
    )


@app.route("/simulate_attack/<int:device_index>")
def simulate_attack(device_index):
    if not require_login("soc"):
        return redirect(url_for("login"))

    devices = load_devices()

    if device_index < 0 or device_index >= len(devices):
        return redirect(url_for("soc_dashboard"))

    behavior = generate_attack_reading(devices[device_index])
    process_device_reading(device_index, behavior, simulated_attack=True)

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
    ensure_single_sensor()
    app.run(host="0.0.0.0", port=5000, debug=True)