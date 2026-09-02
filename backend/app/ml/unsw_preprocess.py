import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer


UNSW_DATASET_PATH = "data/ml/unsw_nb15_testing.csv"

CATEGORICAL_FEATURES = [
    "proto",
    "service",
    "state",
]

TARGET_COLUMN = "label"

NON_FEATURE_COLUMNS = [
    "id",
    "attack_cat",
    TARGET_COLUMN,
]


def load_unsw_nb15(
    path: str = UNSW_DATASET_PATH,
):
    print(f"Loading UNSW-NB15: {path}")

    df = pd.read_csv(path)

    df.columns = (
        df.columns
        .astype(str)
        .str.strip()
    )

    required_columns = {
        "id",
        "attack_cat",
        TARGET_COLUMN,
        *CATEGORICAL_FEATURES,
    }

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            "Missing required UNSW-NB15 columns: "
            f"{sorted(missing)}"
        )

    print("Raw shape:", df.shape)

    # Remove invalid numeric values.
    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True,
    )

    before_invalid = len(df)

    df.dropna(inplace=True)

    print(
        "Invalid rows removed:",
        before_invalid - len(df),
    )

    # ID is unique metadata and must not influence
    # duplicate detection or model training.
    duplicate_subset = [
        column
        for column in df.columns
        if column != "id"
    ]

    before_duplicates = len(df)

    df = df.drop_duplicates(
        subset=duplicate_subset
    ).reset_index(drop=True)

    print(
        "Duplicates removed:",
        before_duplicates - len(df),
    )

    # Validate binary labels.
    valid_labels = {0, 1}

    actual_labels = set(
        df[TARGET_COLUMN]
        .astype(int)
        .unique()
        .tolist()
    )

    if not actual_labels.issubset(valid_labels):
        raise ValueError(
            "UNSW-NB15 contains invalid binary labels: "
            f"{sorted(actual_labels)}"
        )

    X = df.drop(
        columns=NON_FEATURE_COLUMNS
    )

    y = (
        df[TARGET_COLUMN]
        .astype(int)
    )

    print("Final shape:", df.shape)

    print("\nLabel distribution:")
    print(y.value_counts().sort_index())

    return X, y


def split_unsw_nb15(
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


def build_unsw_preprocessor(
    X: pd.DataFrame,
) -> ColumnTransformer:
    categorical_features = [
        column
        for column in CATEGORICAL_FEATURES
        if column in X.columns
    ]

    numeric_features = [
        column
        for column in X.columns
        if column not in categorical_features
    ]

    numeric_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(
                    strategy="median"
                ),
            ),
        ]
    )

    categorical_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(
                    strategy="most_frequent"
                ),
            ),
            (
                "encoder",
                OneHotEncoder(
                    handle_unknown="ignore",
                ),
            ),
        ]
    )

    return ColumnTransformer(
        transformers=[
            (
                "numeric",
                numeric_pipeline,
                numeric_features,
            ),
            (
                "categorical",
                categorical_pipeline,
                categorical_features,
            ),
        ]
    )


if __name__ == "__main__":
    X, y = load_unsw_nb15()

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = split_unsw_nb15(X, y)

    print("\n========== UNSW-NB15 READY ==========")
    print("Features:", X.shape[1])
    print("Training samples:", len(X_train))
    print("Testing samples:", len(X_test))
