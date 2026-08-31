import os

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


DATASET_PATH = "data/ml/suricata_flows.csv"

MODEL_DIR = "app/ml/models"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "suricata_isolation_forest.joblib",
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "suricata_isolation_scaler.joblib",
)


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
    "alerted",
]


def train_model():
    print("Loading Suricata flow dataset...")

    df = pd.read_csv(
        DATASET_PATH
    )

    missing_columns = [
        column
        for column in FEATURE_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            "Missing feature columns: "
            + ", ".join(missing_columns)
        )

    X = df[FEATURE_COLUMNS].copy()

    print(
        "Dataset shape:",
        X.shape,
    )

    # -----------------------------------------------------
    # Scale features
    # -----------------------------------------------------

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(
        X
    )

    # -----------------------------------------------------
    # Train Isolation Forest
    # -----------------------------------------------------

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )

    print(
        "Training Isolation Forest..."
    )

    model.fit(
        X_scaled
    )

    # -----------------------------------------------------
    # Evaluate anomaly distribution
    # -----------------------------------------------------

    predictions = model.predict(
        X_scaled
    )

    anomaly_count = int(
        (predictions == -1).sum()
    )

    normal_count = int(
        (predictions == 1).sum()
    )

    anomaly_rate = (
        anomaly_count / len(X)
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

    # -----------------------------------------------------
    # Save model and scaler
    # -----------------------------------------------------

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
        f"\nModel saved to: {MODEL_PATH}"
    )

    print(
        f"Scaler saved to: {SCALER_PATH}"
    )


if __name__ == "__main__":
    train_model()
