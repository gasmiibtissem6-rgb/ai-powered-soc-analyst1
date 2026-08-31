import joblib
import pandas as pd


MODEL_PATH = (
    "app/ml/models/"
    "network_attack_xgboost.joblib"
)

model = joblib.load(
    MODEL_PATH
)


LABEL_MAPPING = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan",
    3: "FTP-Patator",
    4: "SSH-Patator",
}


def predict_traffic_xgboost(
    features,
):
    """
    Predict network traffic class using
    the trained XGBoost classifier.
    """

    if isinstance(
        features,
        dict,
    ):
        features = pd.DataFrame(
            [features]
        )

    prediction = model.predict(
        features
    )[0]

    probabilities = (
        model.predict_proba(
            features
        )[0]
    )

    prediction_label = (
        LABEL_MAPPING[
            int(prediction)
        ]
    )

    return {
        "prediction": prediction_label,
        "benign_probability": float(
            probabilities[0]
        ),
        "ddos_probability": float(
            probabilities[1]
        ),
        "portscan_probability": float(
            probabilities[2]
        ),
        "ftp_patator_probability": float(
            probabilities[3]
        ),
        "ssh_patator_probability": float(
            probabilities[4]
        ),
    }
