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

from xgboost import XGBClassifier

import joblib
import os

from app.ml.preprocess import load_and_preprocess_data


CLASSES = [0, 1, 2, 3, 4]

CLASS_NAMES = [
    "BENIGN",
    "DDoS",
    "PortScan",
    "FTP-Patator",
    "SSH-Patator",
]


def train_xgboost():
    # 1. Charger exactement les mêmes données
    X, y = load_and_preprocess_data()

    # 2. Même split que Random Forest
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("\nTraining samples:", len(X_train))
    print("Testing samples :", len(X_test))

    # 3. Créer XGBoost multi-classe
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=len(CLASSES),
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )

    print("\nTraining XGBoost...")

    model.fit(
        X_train,
        y_train,
    )

    print("Training completed.")

    # 4. Prédictions
    y_pred = model.predict(
        X_test
    )

    y_proba = model.predict_proba(
        X_test
    )

    # 5. Métriques
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

    y_test_bin = label_binarize(
        y_test,
        classes=CLASSES,
    )

    roc_auc = roc_auc_score(
        y_test_bin,
        y_proba,
        multi_class="ovr",
        average="weighted",
    )

    print(
        "\n========== XGBOOST RESULTS =========="
    )

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    print(f"ROC-AUC   : {roc_auc:.4f}")

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            y_pred,
            labels=CLASSES,
            target_names=CLASS_NAMES,
            zero_division=0,
        )
    )

    # 6. Sauvegarde
    model_dir = "app/ml/models"

    os.makedirs(
        model_dir,
        exist_ok=True,
    )

    model_path = os.path.join(
        model_dir,
        "network_attack_xgboost.joblib",
    )

    joblib.dump(
        model,
        model_path,
    )

    print(
        f"\nModel saved to: {model_path}"
    )


if __name__ == "__main__":
    train_xgboost()
