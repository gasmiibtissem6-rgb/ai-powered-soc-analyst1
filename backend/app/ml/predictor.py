import joblib
import pandas as pd


MODEL_PATH = "app/ml/models/network_attack_random_forest.joblib"

# Charger le modèle entraîné
model = joblib.load(MODEL_PATH)


# Mapping des classes du modèle
LABEL_MAPPING = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan",
    3: "FTP-Patator",
    4: "SSH-Patator",
}


def predict_traffic(features):
    """
    Predict network traffic class:
    BENIGN, DDoS, PortScan, FTP-Patator or SSH-Patator.
    """

    # Transformer le dictionnaire reçu en DataFrame
    if isinstance(features, dict):
        features = pd.DataFrame([features])

    # Faire la prédiction
    prediction = model.predict(features)[0]

    # Récupérer les probabilités pour les 5 classes
    probabilities = model.predict_proba(features)[0]

    # Transformer le numéro de classe en nom
    prediction_label = LABEL_MAPPING[int(prediction)]

    result = {
        "prediction": prediction_label,
        "benign_probability": float(probabilities[0]),
        "ddos_probability": float(probabilities[1]),
        "portscan_probability": float(probabilities[2]),
        "ftp_patator_probability": float(probabilities[3]),
        "ssh_patator_probability": float(probabilities[4]),
    }

    return result