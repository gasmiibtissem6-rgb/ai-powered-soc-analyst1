import joblib
import pandas as pd

from app.ml.suricata_features import (
    extract_suricata_flow_features,
)


MODEL_PATH = (
    "app/ml/models/"
    "suricata_isolation_forest.joblib"
)

SCALER_PATH = (
    "app/ml/models/"
    "suricata_isolation_scaler.joblib"
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
]


model = joblib.load(
    MODEL_PATH
)

scaler = joblib.load(
    SCALER_PATH
)


def predict_suricata_anomaly(event: dict) -> dict:
    """
    Detect whether a Suricata flow is normal
    or anomalous using Isolation Forest.
    """

    features = (
        extract_suricata_flow_features(
            event
        )
    )

    frame = pd.DataFrame(
        [features],
        columns=FEATURE_COLUMNS,
    )

    scaled = scaler.transform(
        frame
    )

    prediction = int(
        model.predict(scaled)[0]
    )

    decision_score = float(
        model.decision_function(
            scaled
        )[0]
    )

    is_anomaly = (
        prediction == -1
    )

    return {
        "status": "success",
        "prediction": (
            "ANOMALY"
            if is_anomaly
            else "NORMAL"
        ),
        "is_anomaly": is_anomaly,
        "anomaly_score": decision_score,
        "features": features,
    }
