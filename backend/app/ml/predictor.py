import joblib
import pandas as pd


MODEL_PATH = "app/ml/models/network_attack_random_forest.joblib"

model = joblib.load(MODEL_PATH)


LABEL_MAPPING = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan",
}


def predict_traffic(features):
    """
    Predict network traffic class:
    BENIGN, DDoS or PortScan.
    """

    # Transformer le dictionnaire reçu en DataFrame
    if isinstance(features, dict):
        features = pd.DataFrame([features])

    # Faire la prédiction
    prediction = model.predict(features)[0]

    # Probabilités pour les 3 classes
    probabilities = model.predict_proba(features)[0]

    # Transformer 0/1/2 en nom de classe
    prediction_label = LABEL_MAPPING[int(prediction)]

    result = {
        "prediction": prediction_label,
        "benign_probability": float(probabilities[0]),
        "ddos_probability": float(probabilities[1]),
        "portscan_probability": float(probabilities[2]),
    }

    return result