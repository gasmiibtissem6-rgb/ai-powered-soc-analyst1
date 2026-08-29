import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
)
from sklearn.preprocessing import label_binarize

from app.ml.preprocess import load_and_preprocess_data


MODEL_PATH = "app/ml/models/network_attack_random_forest.joblib"

LABELS = [0, 1, 2, 3, 4]

TARGET_NAMES = [
    "BENIGN",
    "DDoS",
    "PortScan",
    "FTP-Patator",
    "SSH-Patator",
]


def evaluate_model():
    print("Loading data...")

    X, y = load_and_preprocess_data()

    # Recréer le même découpage train/test
    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("\nLoading trained model...")

    model = joblib.load(MODEL_PATH)

    print("Running predictions...")

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    # Métriques globales
    accuracy = accuracy_score(
        y_test,
        y_pred,
    )

    precision = precision_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    # ROC-AUC multiclasses
    y_test_bin = label_binarize(
        y_test,
        classes=LABELS,
    )

    roc_auc = roc_auc_score(
        y_test_bin,
        y_proba,
        multi_class="ovr",
        average="weighted",
    )

    print("\n========== FINAL MODEL EVALUATION ==========")

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    print(f"ROC-AUC   : {roc_auc:.4f}")

    print("\n========== CLASSIFICATION REPORT ==========")

    print(
        classification_report(
            y_test,
            y_pred,
            labels=LABELS,
            target_names=TARGET_NAMES,
            zero_division=0,
        )
    )


if __name__ == "__main__":
    evaluate_model()