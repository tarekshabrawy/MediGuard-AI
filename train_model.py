"""
train_model.py - MediGuard AI Aligned Three-Model Training

This version trains the models to match the project logic:

1. condition_model.pkl
   Predicts Normal/Critical from sensor readings.

2. anomaly_model.pkl
   Learns safe medical storage behavior and detects abnormal readings.

3. attack_model.pkl
   Predicts Normal Operation / Environmental Failure / Possible Cyber Attack.

This fixes the issue where ML prediction and anomaly were always Critical/Anomalous.
"""

import pandas as pd
import random
import joblib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


FEATURES = [
    "Serial_Reading",
    "_18b20_Temp_C",
    "_18b20_Temp_Fh",
    "Current_humidity",
    "Object_Temperature",
    "NW_cooling"
]


def temp_to_f(temp_c):
    return round((temp_c * 9 / 5) + 32, 2)


def create_row(temp_c, humidity, cooling, label):
    object_temp = round(temp_c + random.uniform(-0.5, 0.8), 2)

    return {
        "Serial_Reading": random.randint(100, 5000),
        "_18b20_Temp_C": temp_c,
        "_18b20_Temp_Fh": temp_to_f(temp_c),
        "Current_humidity": humidity,
        "Object_Temperature": object_temp,
        "NW_cooling": cooling,
        "label": label
    }


# =========================
# CREATE ALIGNED TRAINING DATA
# =========================

rows = []

# Safe / normal readings
for _ in range(2000):
    temp = round(random.uniform(2.0, 8.0), 2)
    humidity = round(random.uniform(40.0, 60.0), 2)
    rows.append(create_row(temp, humidity, 0, 0))

# Warning readings - still not fully critical
for _ in range(1500):
    temp = round(random.uniform(8.0, 12.5), 2)
    humidity = round(random.uniform(55.0, 75.0), 2)
    rows.append(create_row(temp, humidity, 0, 0))

# Critical readings
for _ in range(2000):
    temp = round(random.uniform(13.0, 28.0), 2)
    humidity = round(random.uniform(75.0, 98.0), 2)
    cooling = random.choice([0, 1])
    rows.append(create_row(temp, humidity, cooling, 1))

df = pd.DataFrame(rows)

X = df[FEATURES]
y = df["label"]


# =========================
# MODEL 1: CONDITION MODEL
# =========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

condition_model = RandomForestClassifier(
    n_estimators=120,
    random_state=42
)

condition_model.fit(X_train, y_train)

pred = condition_model.predict(X_test)

print("\n=== Condition Classification Model ===")
print("Accuracy:", accuracy_score(y_test, pred))
print(classification_report(y_test, pred))

joblib.dump(condition_model, "condition_model.pkl")
joblib.dump(condition_model, "model.pkl")


# =========================
# MODEL 2: ANOMALY MODEL
# =========================

normal_data = df[df["label"] == 0][FEATURES]

anomaly_model = IsolationForest(
    contamination=0.12,
    random_state=42
)

anomaly_model.fit(normal_data)

joblib.dump(anomaly_model, "anomaly_model.pkl")

print("\n=== Anomaly Detection Model ===")
print("Anomaly model trained on safe and warning patterns.")


# =========================
# MODEL 3: ATTACK MODEL
# =========================

attack_rows = []

for _ in range(4000):
    environmental_risk = random.randint(0, 100)
    vulnerability_score = random.randint(0, 100)
    anomaly_flag = random.choice([0, 1])
    critical_prediction = 1 if environmental_risk >= 70 else 0

    if environmental_risk < 30:
        attack_label = "Normal Operation"
    elif environmental_risk >= 70 and vulnerability_score >= 60 and anomaly_flag == 1:
        attack_label = "Possible Cyber Attack"
    elif environmental_risk >= 70:
        attack_label = "Environmental Failure"
    elif anomaly_flag == 1 or vulnerability_score >= 60:
        attack_label = "Suspicious Behavior"
    else:
        attack_label = "Environmental Warning"

    attack_rows.append({
        "environmental_risk": environmental_risk,
        "vulnerability_score": vulnerability_score,
        "anomaly_flag": anomaly_flag,
        "critical_prediction": critical_prediction,
        "attack_label": attack_label
    })

attack_df = pd.DataFrame(attack_rows)

attack_X = attack_df[
    [
        "environmental_risk",
        "vulnerability_score",
        "anomaly_flag",
        "critical_prediction"
    ]
]

attack_y = attack_df["attack_label"]

attack_X_train, attack_X_test, attack_y_train, attack_y_test = train_test_split(
    attack_X,
    attack_y,
    test_size=0.2,
    random_state=42
)

attack_model = RandomForestClassifier(
    n_estimators=120,
    random_state=42
)

attack_model.fit(attack_X_train, attack_y_train)

attack_pred = attack_model.predict(attack_X_test)

print("\n=== Attack Detection Model ===")
print("Accuracy:", accuracy_score(attack_y_test, attack_pred))
print(classification_report(attack_y_test, attack_pred))

joblib.dump(attack_model, "attack_model.pkl")

joblib.dump(FEATURES, "feature_columns.pkl")

print("\nAll aligned models trained and saved successfully.")
print("Saved:")
print("- condition_model.pkl")
print("- anomaly_model.pkl")
print("- attack_model.pkl")
print("- model.pkl")
print("- feature_columns.pkl")