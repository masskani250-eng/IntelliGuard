from flask import Flask, request, jsonify
import joblib
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier


app = Flask(__name__)

# Load trained model
model = joblib.load("model.pkl")

# Feature names used by the model
FEATURE_COLUMNS = [
    "request_rate",
    "time_gap_ms",
    "failed_logins",
    "packet_size_kb",
    "payload_entropy"
]


# =========================================================
# HOME
# =========================================================

@app.route("/", methods=["GET"])
def home():
    return "IntelliGuard ML API is running!"


# =========================================================
# PREDICTION
# =========================================================

@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json()

    features = [[
        data["requestRate"],
        data["timeGapMs"],
        data["failedLogins"],
        data["packetSizeKb"],
        data["payloadEntropy"]
    ]]

    prediction = model.predict(features)[0]

    probabilities = model.predict_proba(features)[0]

    confidence = max(probabilities)

    return jsonify({
        "prediction": prediction,
        "confidence": round(float(confidence) * 100, 2)
    })


# =========================================================
# ADAPTIVE FEEDBACK
# =========================================================

@app.route("/feedback", methods=["POST"])
def feedback():

    global model

    data = request.get_json()

    # Required fields
    required_fields = [
        "request_rate",
        "time_gap_ms",
        "failed_logins",
        "packet_size_kb",
        "payload_entropy",
        "label"
    ]

    # Check fields
    for field in required_fields:

        if field not in data:
            return jsonify({
                "error": f"Missing field: {field}"
            }), 400

    feedback_file = "feedback.csv"

    # Create one feedback record
    feedback_row = {
        "request_rate": data["request_rate"],
        "time_gap_ms": data["time_gap_ms"],
        "failed_logins": data["failed_logins"],
        "packet_size_kb": data["packet_size_kb"],
        "payload_entropy": data["payload_entropy"],
        "label": data["label"]
    }

    new_feedback = pd.DataFrame([feedback_row])

    # Save feedback
    file_exists = os.path.exists(feedback_file)

    new_feedback.to_csv(
        feedback_file,
        mode="a",
        header=not file_exists,
        index=False
    )

    # Load original training data
    original_data = pd.read_csv("traffic_data.csv")

    # Load all feedback
    feedback_data = pd.read_csv(feedback_file)

    # Combine old data + human feedback
    combined_data = pd.concat(
        [original_data, feedback_data],
        ignore_index=True
    )

    # Training inputs
    X = combined_data[FEATURE_COLUMNS]

    # Training labels
    y = combined_data["label"]

    # Create new Random Forest
    new_model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    # Retrain
    new_model.fit(X, y)

    # Save updated model
    joblib.dump(new_model, "model.pkl")

    # Use updated model immediately
    model = new_model

    return jsonify({
        "message": "Feedback saved and model retrained successfully!",
        "total_feedback": len(feedback_data)
    })


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000
    )