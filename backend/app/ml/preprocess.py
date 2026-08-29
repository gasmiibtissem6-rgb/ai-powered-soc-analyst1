import pandas as pd
import numpy as np


DDOS_DATASET_PATH = (
    "data/ml/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

PORTSCAN_DATASET_PATH = (
    "data/ml/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)


def load_and_preprocess_data():
    print("Loading datasets...")

    # Charger les deux datasets
    ddos_df = pd.read_csv(DDOS_DATASET_PATH)
    portscan_df = pd.read_csv(PORTSCAN_DATASET_PATH)

    # Nettoyer les noms des colonnes
    ddos_df.columns = ddos_df.columns.str.strip()
    portscan_df.columns = portscan_df.columns.str.strip()

    print("DDoS dataset shape:", ddos_df.shape)
    print("PortScan dataset shape:", portscan_df.shape)

    # Fusionner les datasets
    df = pd.concat(
        [ddos_df, portscan_df],
        ignore_index=True,
    )

    print("\nCombined shape:", df.shape)

    # Remplacer inf / -inf par NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Supprimer les lignes avec valeurs manquantes
    df.dropna(inplace=True)

    print("Shape after cleaning:", df.shape)

    # Nettoyer les labels
    df["Label"] = df["Label"].astype(str).str.strip()

    # Garder uniquement les classes voulues
    df = df[df["Label"].isin(["BENIGN", "DDoS", "PortScan"])]

    # Conversion des labels en nombres
    label_mapping = {
        "BENIGN": 0,
        "DDoS": 1,
        "PortScan": 2,
    }

    df["Label"] = df["Label"].map(label_mapping)

    # Séparation features / target
    X = df.drop(columns=["Label"])
    y = df["Label"]

    print("\nLabel distribution:")
    print(y.value_counts().sort_index())

    print("\nLabel mapping:")
    print("0 = BENIGN")
    print("1 = DDoS")
    print("2 = PortScan")

    print("\nFeatures shape:", X.shape)
    print("Target shape:", y.shape)

    return X, y


if __name__ == "__main__":
    X, y = load_and_preprocess_data()