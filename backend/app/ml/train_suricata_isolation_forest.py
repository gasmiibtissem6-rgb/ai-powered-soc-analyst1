import os
import json

import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


DATASET_PATH = "data/ml/suricata_flows.csv"

MODEL_DIR = "app/ml/models"

EVALUATION_DIR = "app/ml/evaluation"


MODEL_PATH = os.path.join(
    MODEL_DIR,
    "suricata_isolation_forest.joblib",
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "suricata_isolation_scaler.joblib",
)

METRICS_PATH = os.path.join(
    EVALUATION_DIR,
    "suricata_metrics.json",
)


# alerted is only used for evaluation
# It is NOT used as model input
FEATURE_COLUMNS = [
    "destination_port",
    "duration_seconds",
    "pkts_to_server",
    "pkts_to_client",
    "bytes_to_server",
    "bytes_to_client",
    "total_packets",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "syn_flag",
    "fin_flag",
    "psh_flag",
    "ack_flag",
]


def train_model():

    print("Loading Suricata flow dataset...")

    df = pd.read_csv(
        DATASET_PATH
    )


    missing_columns = [
        column
        for column in FEATURE_COLUMNS + ["alerted"]
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            "Missing columns: "
            + ", ".join(missing_columns)
        )


    X = df[
        FEATURE_COLUMNS
    ].copy()


    # Ground truth for evaluation only
    y_true = (
        df["alerted"]
        .astype(int)
    )


    print(
        "Dataset shape:",
        X.shape,
    )


    # =====================================================
    # SCALE FEATURES
    # =====================================================

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(
        X
    )


    # =====================================================
    # TRAIN ISOLATION FOREST
    # =====================================================

    model = IsolationForest(
    n_estimators=300,
    contamination=0.01,
    random_state=42,
    n_jobs=-1,
)


    print(
        "Training Isolation Forest..."
    )


    model.fit(
        X_scaled
    )


    # =====================================================
    # PREDICTION
    # =====================================================

    predictions = model.predict(
        X_scaled
    )


    # Isolation Forest:
    # -1 = anomaly
    #  1 = normal

    y_pred = (
        predictions == -1
    ).astype(int)


    anomaly_count = int(
        (y_pred == 1).sum()
    )

    normal_count = int(
        (y_pred == 0).sum()
    )


    anomaly_rate = (
        anomaly_count / len(X)
    )


    # =====================================================
    # EVALUATION METRICS
    # =====================================================

    accuracy = accuracy_score(
        y_true,
        y_pred,
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0,
    )


    cm = confusion_matrix(
        y_true,
        y_pred,
    )


    print(
        "\n========== ISOLATION FOREST RESULTS =========="
    )

    print(
        "Normal flows :",
        normal_count,
    )

    print(
        "Anomalies    :",
        anomaly_count,
    )

    print(
        f"Anomaly rate : {anomaly_rate:.4f}"
    )


    print(
        "\n========== DETECTION METRICS =========="
    )

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )


    print(
        "\nConfusion Matrix:"
    )

    print(cm)


    # =====================================================
    # SAVE METRICS
    # =====================================================

    os.makedirs(
        EVALUATION_DIR,
        exist_ok=True,
    )


    metrics = {
        "model": "Suricata Isolation Forest",
        "dataset_size": int(len(X)),

        "normal_flows": normal_count,
        "anomalies_detected": anomaly_count,

        "anomaly_rate": float(
            anomaly_rate
        ),

        "accuracy": float(
            accuracy
        ),

        "precision": float(
            precision
        ),

        "recall": float(
            recall
        ),

        "f1_score": float(
            f1
        ),

        "confusion_matrix": (
            cm.tolist()
        ),
    }


    with open(
        METRICS_PATH,
        "w",
    ) as file:

        json.dump(
            metrics,
            file,
            indent=4,
        )


    print(
        f"\nMetrics saved to: {METRICS_PATH}"
    )


    # =====================================================
    # SAVE MODEL + SCALER
    # =====================================================

    os.makedirs(
        MODEL_DIR,
        exist_ok=True,
    )


    joblib.dump(
        model,
        MODEL_PATH,
    )


    joblib.dump(
        scaler,
        SCALER_PATH,
    )


    print(
        f"Model saved to: {MODEL_PATH}"
    )

    print(
        f"Scaler saved to: {SCALER_PATH}"
    )


if __name__ == "__main__":
    train_model()