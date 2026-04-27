"""
train_model.py

This file trains the Machine Learning model for the Smart Home AI Security project.

What it does:
1. Reads the IoT behavior dataset from data/dataset.csv.
2. Converts device type text into numbers because ML models need numerical data.
3. Trains a Random Forest model to classify behavior as normal or suspicious.
4. Saves the trained model as model.pkl.
5. Saves the encoder as encoder.pkl so the website can understand device types later.
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

# Read the dataset file from the data folder
df = pd.read_csv("data/dataset.csv")

# Create an encoder to convert device type names into numbers
encoder = LabelEncoder()

# Convert device_type column from text into numbers
df["device_type"] = encoder.fit_transform(df["device_type"])

# X contains the input features used by the model to learn behavior
X = df[
    [
        "device_type",
        "packet_rate",
        "avg_packet_size",
        "connection_count",
        "bytes_sent",
        "bytes_received",
        "failed_connections",
    ]
]

# y contains the correct answer: normal or suspicious
y = df["label"]

# Create the Random Forest classifier model
model = RandomForestClassifier(random_state=42)

# Train the model using the dataset
model.fit(X, y)

# Save the trained model so app.py can use it later
joblib.dump(model, "model.pkl")

# Save the encoder so app.py can convert device types in the same way
joblib.dump(encoder, "encoder.pkl")

# Print success message
print("Model trained and saved successfully.")