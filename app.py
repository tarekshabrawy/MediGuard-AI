"""
app.py - Medical Storage AI Risk Monitoring Dashboard (Version 0.2)

This is the main Flask application file for the Medical Storage AI Risk Monitoring Dashboard.

What it does:
1. Loads the trained Machine Learning model (model.pkl).
2. Loads devices from data/devices.csv dynamically.
3. Allows the user to add new devices via /add_device.
4. Simulates safe, warning, or critical medical storage conditions.
5. Uses the ML model to predict storage condition.
6. Calculates risk score from 0% to 100%.
7. Saves all monitoring results to logs.csv.
"""

from flask import Flask, render_template, redirect, request, url_for
import joblib
import csv
import os
import random
from datetime import datetime

# Create Flask application
app = Flask(__name__)

# Load trained ML model
model = joblib.load("model.pkl")

# File paths
DEVICES_FILE = "data/devices.csv"
LOG_FILE = "logs.csv"


def load_devices():
    """
    Load devices from data/devices.csv.

    This function safely handles empty CSV cells.
    For example, if risk_score is empty, it becomes 0 instead of crashing.
    """
    devices = []

    if os.path.exists(DEVICES_FILE):
        with open(DEVICES_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)

            for row in reader:
                # Convert risk_score safely.
                # If the value is empty, use 0.
                risk_score = int(row.get("risk_score") or 0)

                device = {
                    "device_name": row.get("device_name", ""),
                    "device_type": row.get("device_type", ""),
                    "location": row.get("location", ""),
                    "storage_type": row.get("storage_type", ""),
                    "temperature_c": row.get("temperature_c") or "-",
                    "humidity": row.get("humidity") or "-",
                    "object_temperature": row.get("object_temperature") or "-",
                    "cooling_status": row.get("cooling_status") or "-",
                    "status": row.get("status") or "No Data",
                    "risk_score": risk_score,
                    "risk_level": row.get("risk_level") or "-",
                    "action": row.get("action") or "-"
                }

                devices.append(device)

    return devices


def save_device(device_name, device_type, location, storage_type):
    """
    Save a new user-added device to data/devices.csv.
    """

    # Make sure data folder exists
    os.makedirs("data", exist_ok=True)

    file_exists = os.path.exists(DEVICES_FILE)

    with open(DEVICES_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        # Write header if file does not exist
        if not file_exists:
            writer.writerow([
                "device_name",
                "device_type",
                "location",
                "storage_type",
                "temperature_c",
                "humidity",
                "object_temperature",
                "cooling_status",
                "status",
                "risk_score",
                "risk_level",
                "action"
            ])

        # Add new device with empty monitoring values
        writer.writerow([
            device_name,
            device_type,
            location,
            storage_type,
            "",
            "",
            "",
            "",
            "No Data",
            0,
            "-",
            "-"
        ])


def update_device_readings(device_index, updated_data):
    """
    Update one device row in data/devices.csv after monitoring/simulation.
    """

    if not os.path.exists(DEVICES_FILE):
        return

    # Read all devices
    with open(DEVICES_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)
        devices = list(reader)

    # Validate index
    if device_index < 0 or device_index >= len(devices):
        return

    # Update selected device row
    devices[device_index]["temperature_c"] = updated_data.get("temperature_c", "-")
    devices[device_index]["humidity"] = updated_data.get("humidity", "-")
    devices[device_index]["object_temperature"] = updated_data.get("object_temperature", "-")
    devices[device_index]["cooling_status"] = updated_data.get("cooling_status", "-")
    devices[device_index]["status"] = updated_data.get("status", "No Data")
    devices[device_index]["risk_score"] = updated_data.get("risk_score", 0)
    devices[device_index]["risk_level"] = updated_data.get("risk_level", "-")
    devices[device_index]["action"] = updated_data.get("action", "-")

    # Save all devices again
    fieldnames = [
        "device_name",
        "device_type",
        "location",
        "storage_type",
        "temperature_c",
        "humidity",
        "object_temperature",
        "cooling_status",
        "status",
        "risk_score",
        "risk_level",
        "action"
    ]

    with open(DEVICES_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(devices)


def generate_readings(mode):
    """
    Generate realistic medical storage readings for demo/testing.

    In the real product, these readings would come from actual sensors.
    """

    if mode == "safe":
        # Safe: temperature 2–8°C, humidity 40–60%, cooling normal
        return {
            "serial_reading": random.randint(50, 200),
            "temp_c": round(random.uniform(2.0, 8.0), 2),
            "temp_fh": round(random.uniform(35.6, 46.4), 2),
            "humidity": round(random.uniform(40.0, 60.0), 2),
            "object_temp": round(random.uniform(2.0, 8.0), 2),
            "nw_cooling": 0
        }

    elif mode == "warning":
        # Warning: temperature slightly high or humidity slightly high
        if random.choice([True, False]):
            return {
                "serial_reading": random.randint(200, 500),
                "temp_c": round(random.uniform(8.0, 12.0), 2),
                "temp_fh": round(random.uniform(46.4, 53.6), 2),
                "humidity": round(random.uniform(40.0, 60.0), 2),
                "object_temp": round(random.uniform(8.0, 12.0), 2),
                "nw_cooling": 0
            }
        else:
            return {
                "serial_reading": random.randint(200, 500),
                "temp_c": round(random.uniform(2.0, 8.0), 2),
                "temp_fh": round(random.uniform(35.6, 46.4), 2),
                "humidity": round(random.uniform(60.0, 75.0), 2),
                "object_temp": round(random.uniform(2.0, 8.0), 2),
                "nw_cooling": 0
            }

    else:
        # Critical: high temperature, high humidity, or cooling failure
        return {
            "serial_reading": random.randint(500, 2000),
            "temp_c": round(random.uniform(12.0, 25.0), 2),
            "temp_fh": round(random.uniform(53.6, 77.0), 2),
            "humidity": round(random.uniform(75.0, 95.0), 2),
            "object_temp": round(random.uniform(12.0, 25.0), 2),
            "nw_cooling": random.choice([0, 1])
        }


def calculate_risk_score(behavior, ml_prediction):
    """
    Calculate risk score from 0 to 100.

    The final risk depends on:
    1. ML model prediction.
    2. Temperature range.
    3. Humidity range.
    4. Cooling system status.
    """

    risk_score = 0

    # ML model risk
    if ml_prediction == 1:
        risk_score += 60

    # Temperature risk
    temp_c = behavior["temp_c"]

    if temp_c > 8:
        risk_score += 15
    if temp_c > 12:
        risk_score += 15
    if temp_c > 20:
        risk_score += 10
    if temp_c < -25:
        risk_score += 10

    # Humidity risk
    humidity = behavior["humidity"]

    if humidity > 60:
        risk_score += 10
    if humidity > 75:
        risk_score += 10
    if humidity > 85:
        risk_score += 10

    # Cooling failure risk
    if behavior["nw_cooling"] == 1:
        risk_score += 10

    return min(risk_score, 100)


def predict_condition(behavior):
    """
    Send readings to the ML model and return:
    status, risk level, action, risk score, and ML prediction.
    """

    # Features must match the order used during model training
    features = [[
        behavior["serial_reading"],
        behavior["temp_c"],
        behavior["temp_fh"],
        behavior["humidity"],
        behavior["object_temp"],
        behavior["nw_cooling"]
    ]]

    # Predict condition: 0 = normal, 1 = critical
    ml_prediction = model.predict(features)[0]

    # Calculate risk score
    risk_score = calculate_risk_score(behavior, ml_prediction)

    # Risk matrix
    if risk_score < 30:
        status = "Normal"
        risk_level = "Low"
        action = "Continue Monitoring"
    elif risk_score < 70:
        status = "Warning"
        risk_level = "Medium"
        action = "Alert Admin"
    else:
        status = "Critical"
        risk_level = "High"
        action = "Immediate Action Required"

    return status, risk_level, action, risk_score, ml_prediction


def save_log(device_name, device_type, location, storage_type, behavior, ml_prediction, risk_score, risk_level, action):
    """
    Save each monitoring result to logs.csv.
    """

    file_exists = os.path.exists(LOG_FILE)

    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        # Write header if logs.csv does not exist
        if not file_exists:
            writer.writerow([
                "time",
                "device_name",
                "device_type",
                "location",
                "storage_type",
                "temperature_c",
                "humidity",
                "object_temperature",
                "cooling_status",
                "ml_prediction",
                "risk_score",
                "risk_level",
                "action"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            device_name,
            device_type,
            location,
            storage_type,
            behavior["temp_c"],
            behavior["humidity"],
            behavior["object_temp"],
            "Normal" if behavior["nw_cooling"] == 0 else "Failure",
            ml_prediction,
            risk_score,
            risk_level,
            action
        ])


@app.route("/")
def dashboard():
    """
    Display the main dashboard.
    Devices are loaded dynamically from data/devices.csv.
    """

    devices = load_devices()
    return render_template("index.html", devices=devices)


@app.route("/add_device", methods=["GET", "POST"])
def add_device():
    """
    Add new medical storage sensor/device.
    """

    if request.method == "POST":
        device_name = request.form.get("device_name")
        device_type = request.form.get("device_type")
        location = request.form.get("location")
        storage_type = request.form.get("storage_type")

        save_device(device_name, device_type, location, storage_type)

        return redirect(url_for("dashboard"))

    return render_template("add_device.html")


@app.route("/simulate/<int:device_index>/<mode>")
def simulate(device_index, mode):
    """
    Simulate safe/warning/critical sensor readings for a selected device.

    Demo note:
    In the real system, this route would be replaced by live sensor readings.
    """

    devices = load_devices()

    # Validate selected device
    if device_index < 0 or device_index >= len(devices):
        return redirect(url_for("dashboard"))

    device = devices[device_index]

    # Generate readings
    behavior = generate_readings(mode)

    # Predict condition and calculate risk
    status, risk_level, action, risk_score, ml_prediction = predict_condition(behavior)

    # Prepare updated dashboard data
    updated_data = {
        "temperature_c": behavior["temp_c"],
        "humidity": behavior["humidity"],
        "object_temperature": behavior["object_temp"],
        "cooling_status": "Normal" if behavior["nw_cooling"] == 0 else "Failure",
        "status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": action
    }

    # Update devices.csv
    update_device_readings(device_index, updated_data)

    # Save log
    save_log(
        device["device_name"],
        device["device_type"],
        device["location"],
        device["storage_type"],
        behavior,
        ml_prediction,
        risk_score,
        risk_level,
        action
    )

    return redirect(url_for("dashboard"))


@app.route("/logs")
def logs():
    """
    Display monitoring logs.
    """

    logs_data = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            reader = csv.DictReader(file)
            logs_data = list(reader)

    return render_template("logs.html", logs=logs_data)


# Run Flask app
if __name__ == "__main__":
    app.run(debug=True)