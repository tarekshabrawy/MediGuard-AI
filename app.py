"""
app.py

This is the main Flask website file for the Smart Home AI Security Dashboard.

What it does:
1. Loads the trained Machine Learning model.
2. Displays IoT devices on the dashboard.
3. Simulates normal behavior or attack behavior.
4. Uses the ML model to classify the behavior.
5. Shows the result as Authenticated or Suspicious.
6. Saves every result in logs.csv.
"""

from flask import Flask, render_template, redirect
import joblib
import csv
import os
from datetime import datetime

# Create the Flask application
app = Flask(__name__)

# Load the trained ML model
model = joblib.load("model.pkl")

# Load the encoder that converts device types into numbers
encoder = joblib.load("encoder.pkl")

# File where security logs will be saved
LOG_FILE = "logs.csv"

# If logs.csv does not exist, create it with column names
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["time", "device_name", "device_type", "status", "risk_level", "action"])


# List of smart home IoT devices shown on the dashboard
devices = [
    {"name": "Living Room Temperature Sensor", "type": "temperature_sensor"},
    {"name": "Kitchen Gas Sensor", "type": "gas_sensor"},
    {"name": "Main Door Lock", "type": "door_lock"},
    {"name": "Front Camera", "type": "camera"},
    {"name": "Bedroom Smart Light", "type": "smart_light"},
]


def predict_behavior(device_type, behavior):
    """
    This function sends device behavior data to the ML model.

    Input:
    - device_type: type of IoT device
    - behavior: traffic/activity values

    Output:
    - status: Authenticated or Suspicious
    - risk_level: Low or High
    - action: Allow Access or Block / Alert Admin
    """

    # Convert device type text into the number used during training
    device_type_encoded = encoder.transform([device_type])[0]

    # Arrange input features in the same order used in train_model.py
    features = [[
        device_type_encoded,
        behavior["packet_rate"],
        behavior["avg_packet_size"],
        behavior["connection_count"],
        behavior["bytes_sent"],
        behavior["bytes_received"],
        behavior["failed_connections"]
    ]]

    # Predict if behavior is normal or suspicious
    prediction = model.predict(features)[0]

    # Convert prediction into dashboard-friendly output
    if prediction == "normal":
        return "Authenticated", "Low", "Allow Access"
    else:
        return "Suspicious", "High", "Block / Alert Admin"


def save_log(device_name, device_type, status, risk_level, action):
    """
    This function saves each authentication result in logs.csv.
    """

    # Open logs.csv and add a new row
    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), device_name, device_type, status, risk_level, action])


@app.route("/")
def dashboard():
    """
    This route displays the main dashboard page.
    """

    # Send the devices list to index.html
    return render_template("index.html", devices=devices)


@app.route("/simulate/<int:device_index>/<mode>")
def simulate(device_index, mode):
    """
    This route simulates normal or attack behavior for a selected device.
    """

    # Select the device based on its index in the devices list
    device = devices[device_index]

    # Normal behavior simulation
    if mode == "normal":
        behavior = {
            "packet_rate": 5,
            "avg_packet_size": 300,
            "connection_count": 2,
            "bytes_sent": 1500,
            "bytes_received": 1200,
            "failed_connections": 0
        }

    # Attack behavior simulation
    else:
        behavior = {
            "packet_rate": 75,
            "avg_packet_size": 2300,
            "connection_count": 25,
            "bytes_sent": 70000,
            "bytes_received": 55000,
            "failed_connections": 10
        }

    # Use the ML model to classify the behavior
    status, risk_level, action = predict_behavior(device["type"], behavior)

    # Store the result inside the device dictionary so the dashboard can show it
    device["status"] = status
    device["risk_level"] = risk_level
    device["action"] = action

    # Save the result in logs.csv
    save_log(device["name"], device["type"], status, risk_level, action)

    # Return to the dashboard after simulation
    return redirect("/")


@app.route("/logs")
def logs():
    """
    This route displays the logs page.
    """

    logs_data = []

    # Read saved logs from logs.csv
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            reader = csv.DictReader(file)
            logs_data = list(reader)

    # Send logs data to logs.html
    return render_template("logs.html", logs=logs_data)


# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)