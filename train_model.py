# train_model.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Load the dataset
dataset = pd.read_csv('data/medical_storage_dataset.csv')

# Clean up column names (strip extra spaces)
dataset.columns = dataset.columns.str.replace(' ', '_')

# Check the first few rows to understand the dataset
print(dataset.head())

# Preprocessing the dataset: 
# Feature columns are everything except 'Critical_Level'
X = dataset.drop(columns=['Critical_Level'])

# Target column is 'Critical_Level'
y = dataset['Critical_Level']

# Split the data into training and testing sets (80% training, 20% testing)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize the model
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the model
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Print classification report (accuracy, precision, recall, F1-score)
print(classification_report(y_test, y_pred))

# Save the trained model
joblib.dump(model, 'model.pkl')

# Save the encoder (if needed in the future)
joblib.dump(X.columns, 'encoder.pkl')