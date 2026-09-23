import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


# Load the dataset
df = pd.read_csv("traffic_data.csv")


# Features used by the AI
X = df[
    [
        "request_rate",
        "time_gap_ms",
        "failed_logins",
        "packet_size_kb",
        "payload_entropy"
    ]
]


# Correct answer for each row
y = df["label"]


# Split data into training and testing
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# Create Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# Train the AI
model.fit(X_train, y_train)


# Test the AI
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("Model training completed!")
print("Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(y_test, predictions))


# Save the trained model
joblib.dump(model, "model.pkl")

print("\nModel saved as model.pkl")