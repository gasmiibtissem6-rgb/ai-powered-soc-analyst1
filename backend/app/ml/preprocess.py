import pandas as pd
import numpy as np


DDOS_DATASET_PATH = (
    "data/ml/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

PORTSCAN_DATASET_PATH = (
    "data/ml/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)

TUESDAY_DATASET_PATH = (
    "data/ml/Tuesday-WorkingHours.pcap_ISCX.csv"
)


LABEL_MAPPING = {
    "BENIGN": 0,
    "DDoS": 1,
    "PortScan": 2,
    "FTP-Patator": 3,
    "SSH-Patator": 4,
}


def prepare_dataset(path, allowed_labels, max_per_class=15000):
    print(f"Loading: {path}")

    df = pd.read_csv(path)

    # Nettoyer les noms des colonnes
    df.columns = df.columns.str.strip()

    # Nettoyer les labels
    df["Label"] = df["Label"].astype(str).str.strip()

    # Garder seulement les classes nécessaires
    df = df[df["Label"].isin(allowed_labels)]

    # Limiter le nombre d'exemples par classe
    sampled_parts = []

    for label in allowed_labels:
        class_df = df[df["Label"] == label]

        if len(class_df) > max_per_class:
            class_df = class_df.sample(
                n=max_per_class,
                random_state=42,
            )

        sampled_parts.append(class_df)

    result = pd.concat(
        sampled_parts,
        ignore_index=True,
    )

    del df

    return result


def load_and_preprocess_data():
    print("Loading datasets with memory optimization...\n")

    # =====================================================
    # 1. Charger les datasets
    # =====================================================

    ddos_df = prepare_dataset(
        DDOS_DATASET_PATH,
        ["BENIGN", "DDoS"],
    )

    portscan_df = prepare_dataset(
        PORTSCAN_DATASET_PATH,
        ["BENIGN", "PortScan"],
    )

    tuesday_df = prepare_dataset(
        TUESDAY_DATASET_PATH,
        ["BENIGN", "FTP-Patator", "SSH-Patator"],
    )

    # =====================================================
    # 2. Fusionner les datasets
    # =====================================================

    print("\nCombining datasets...")

    df = pd.concat(
        [
            ddos_df,
            portscan_df,
            tuesday_df,
        ],
        ignore_index=True,
    )

    del ddos_df
    del portscan_df
    del tuesday_df

    print("Combined shape:", df.shape)

    # =====================================================
    # 3. Nettoyer les valeurs invalides
    # =====================================================

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True,
    )

    before_invalid = len(df)

    df.dropna(inplace=True)

    after_invalid = len(df)

    print(
        f"Invalid rows removed: "
        f"{before_invalid - after_invalid}"
    )

    # =====================================================
    # 4. Supprimer les doublons
    # IMPORTANT : avant le train/test split
    # =====================================================

    print("\nRemoving duplicate rows...")

    before_duplicates = len(df)

    df = df.drop_duplicates().reset_index(drop=True)

    after_duplicates = len(df)

    print(
        f"Rows before duplicate removal: "
        f"{before_duplicates}"
    )

    print(
        f"Rows after duplicate removal : "
        f"{after_duplicates}"
    )

    print(
        f"Duplicates removed           : "
        f"{before_duplicates - after_duplicates}"
    )

    # =====================================================
    # 5. Convertir les labels
    # =====================================================

    df["Label"] = df["Label"].map(LABEL_MAPPING)

    # Vérification de sécurité
    if df["Label"].isna().any():
        raise ValueError(
            "Unknown labels detected after label mapping."
        )

    # =====================================================
    # 6. Mélanger les données
    # =====================================================

    df = df.sample(
        frac=1,
        random_state=42,
    ).reset_index(drop=True)

    # =====================================================
    # 7. Séparer Features / Target
    # =====================================================

    X = df.drop(columns=["Label"])
    y = df["Label"]

    # =====================================================
    # 8. Afficher les informations finales
    # =====================================================

    print("\n========== DATASET READY ==========")

    print("\nLabel distribution:")
    print(y.value_counts().sort_index())

    print("\nLabel mapping:")

    for label, number in LABEL_MAPPING.items():
        print(f"{number} = {label}")

    print("\nFeatures shape:", X.shape)
    print("Target shape:", y.shape)

    return X, y


if __name__ == "__main__":
    X, y = load_and_preprocess_data()