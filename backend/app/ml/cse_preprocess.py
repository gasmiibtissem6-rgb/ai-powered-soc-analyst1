import joblib
import pandas as pd

from sklearn.model_selection import train_test_split

from app.ml.dataset_adapters import DatasetAdapter


DATASET_PATH = "data/ml/cse_cic_ids2018_sample.csv"

REFERENCE_MODEL_PATH = (
    "app/ml/models/network_attack_random_forest.joblib"
)


def load_cse_cic_ids2018(
    path: str = DATASET_PATH,
):
    print(f"Loading CSE-CIC-IDS2018: {path}")

    model = joblib.load(REFERENCE_MODEL_PATH)

    if not hasattr(model, "feature_names_in_"):
        raise ValueError(
            "Reference CICIDS2017 model does not contain "
            "feature_names_in_."
        )

    reference_features = list(
        model.feature_names_in_
    )

    adapter = DatasetAdapter(
        "cse-cic-ids2018"
    )

    df = adapter.load(path)

    print("Raw shape:", df.shape)

    df = adapter.normalize_labels(df)

    labels = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    # Binary target:
    # Benign -> 0
    # Any attack -> 1
    y = (
        labels
        .str.lower()
        .ne("benign")
        .astype(int)
    )

    X = adapter.align_cse_cic_ids2018_to_cicids2017(
        df,
        reference_features,
    )

    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    X = X.replace(
        [float("inf"), float("-inf")],
        pd.NA,
    )

    # Remove invalid rows while keeping X/y synchronized.
    valid_mask = ~X.isna().any(axis=1)

    invalid_rows = int(
        (~valid_mask).sum()
    )

    X = (
        X.loc[valid_mask]
        .reset_index(drop=True)
    )

    y = (
        y.loc[valid_mask]
        .reset_index(drop=True)
    )

    print(
        "Invalid rows removed:",
        invalid_rows,
    )

    # Remove duplicates BEFORE train/test split.
    combined = X.copy()
    combined["__target__"] = y

    before_duplicates = len(combined)

    combined = (
        combined
        .drop_duplicates()
        .reset_index(drop=True)
    )

    duplicates_removed = (
        before_duplicates - len(combined)
    )

    print(
        "Duplicates removed:",
        duplicates_removed,
    )

    y = (
        combined
        .pop("__target__")
        .astype(int)
    )

    X = combined

    if list(X.columns) != reference_features:
        raise ValueError(
            "CSE-CIC-IDS2018 feature schema does not "
            "match the CICIDS2017 feature schema."
        )

    print("Final shape:", X.shape)

    print("\nLabel distribution:")
    print(
        y.value_counts()
        .sort_index()
    )

    print("\nLabel mapping:")
    print("0 = Benign")
    print("1 = Attack")

    return X, y


def split_cse_cic_ids2018(
    X: pd.DataFrame,
    y: pd.Series,
):
    return train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )


if __name__ == "__main__":
    X, y = load_cse_cic_ids2018()

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = split_cse_cic_ids2018(
        X,
        y,
    )

    print(
        "\n========== CSE-CIC-IDS2018 READY =========="
    )

    print("Features        :", X.shape[1])
    print("Training samples:", len(X_train))
    print("Testing samples :", len(X_test))
