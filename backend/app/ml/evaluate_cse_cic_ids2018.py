import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

from app.ml.dataset_adapters import DatasetAdapter


DATASET_PATH = "data/ml/cse_cic_ids2018_sample.csv"

MODEL_PATH = (
    "app/ml/models/network_attack_random_forest.joblib"
)


def evaluate_cse_cic_ids2018():
    print("Loading trained CICIDS2017 model...")

    model = joblib.load(MODEL_PATH)

    if not hasattr(model, "feature_names_in_"):
        raise ValueError(
            "The trained model does not contain "
            "feature_names_in_."
        )

    reference_features = list(
        model.feature_names_in_
    )

    print("Model features:", len(reference_features))
    print("Model classes :", model.classes_)

    # -------------------------------------------------
    # Load CSE-CIC-IDS2018
    # -------------------------------------------------

    print("\nLoading CSE-CIC-IDS2018...")

    adapter = DatasetAdapter(
        "cse-cic-ids2018"
    )

    df = adapter.load(DATASET_PATH)

    print("Raw shape:", df.shape)

    # -------------------------------------------------
    # Normalize labels
    # -------------------------------------------------

    df = adapter.normalize_labels(df)

    print("Shape after label normalization:", df.shape)

    print("\nOriginal label distribution:")
    print(
        df["Label"]
        .astype(str)
        .str.strip()
        .value_counts()
    )

    # -------------------------------------------------
    # Binary ground truth
    #
    # Benign traffic -> 0
    # Any attack     -> 1
    # -------------------------------------------------

    labels = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    y_true = (
        labels
        .str.lower()
        .ne("benign")
        .astype(int)
    )

    # -------------------------------------------------
    # Align CSE features to CICIDS2017 schema
    # -------------------------------------------------

    X = adapter.align_cse_cic_ids2018_to_cicids2017(
        df,
        reference_features,
    )

    print("\nAligned features:", X.shape[1])

    if list(X.columns) != reference_features:
        raise ValueError(
            "CSE-CIC-IDS2018 feature order does not "
            "match the trained CICIDS2017 model."
        )

    # -------------------------------------------------
    # Numeric cleaning
    # -------------------------------------------------

    # Keep y synchronized with rows that survive cleaning.
    X_numeric = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    X_numeric = X_numeric.replace(
        [float("inf"), float("-inf")],
        pd.NA,
    )

    valid_mask = ~X_numeric.isna().any(axis=1)

    invalid_rows = int((~valid_mask).sum())

    X = (
        X_numeric.loc[valid_mask]
        .reset_index(drop=True)
    )

    y_true = (
        y_true.loc[valid_mask]
        .reset_index(drop=True)
    )

    print("Invalid rows removed:", invalid_rows)
    print("Evaluation rows    :", len(X))

    if len(X) == 0:
        raise ValueError(
            "No valid rows remain for evaluation."
        )

    print("\nBinary ground-truth distribution:")
    print(y_true.value_counts().sort_index())

    # -------------------------------------------------
    # Model predictions
    # -------------------------------------------------

    print("\nRunning external predictions...")

    multiclass_predictions = model.predict(X)

    multiclass_probabilities = model.predict_proba(X)

    # CICIDS model:
    # 0 = BENIGN
    # 1..4 = known attack classes
    #
    # For external binary evaluation:
    # 0 -> Normal
    # anything else -> Attack

    y_pred = (
        multiclass_predictions != 0
    ).astype(int)

    # Probability of "Attack" =
    # 1 - probability assigned to BENIGN.

    classes = list(model.classes_)

    if 0 not in classes:
        raise ValueError(
            "BENIGN class 0 was not found in model.classes_."
        )

    benign_index = classes.index(0)

    attack_probability = (
        1.0
        - multiclass_probabilities[:, benign_index]
    )

    # -------------------------------------------------
    # Metrics
    # -------------------------------------------------

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

    roc_auc = roc_auc_score(
        y_true,
        attack_probability,
    )

    # -------------------------------------------------
    # Results
    # -------------------------------------------------

    print(
        "\n========== CSE-CIC-IDS2018 "
        "EXTERNAL BINARY EVALUATION =========="
    )

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"ROC-AUC  : {roc_auc:.4f}")

    print(
        "\n========== CLASSIFICATION REPORT =========="
    )

    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            target_names=[
                "Normal",
                "Attack",
            ],
            digits=4,
            zero_division=0,
        )
    )

    print(
        "\n========== CONFUSION MATRIX =========="
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    )

    print(matrix)

    tn, fp, fn, tp = matrix.ravel()

    print("\nTN:", tn)
    print("FP:", fp)
    print("FN:", fn)
    print("TP:", tp)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "evaluation_rows": len(X),
    }


if __name__ == "__main__":
    evaluate_cse_cic_ids2018()
