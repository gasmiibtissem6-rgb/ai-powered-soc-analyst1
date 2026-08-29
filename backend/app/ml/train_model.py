from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
)
from sklearn.preprocessing import label_binarize

import joblib
import os

from app.ml.preprocess import load_and_preprocess_data


def train_model():
    # 1. Charger et nettoyer les données
    X, y = load_and_preprocess_data()

    # 2. Séparer les données en train / test
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("\nTraining samples:", len(X_train))
    print("Testing samples:", len(X_test))

    # 3. Créer le modèle Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )

    # 4. Entraîner le modèle
    print("\nTraining Random Forest...")

    model.fit(X_train, y_train)

    print("Training completed.")

    # 5. Faire les prédictions
    y_pred = model.predict(X_test)

    # Probabilités pour chaque classe
    y_proba = model.predict_proba(X_test)

    # 6. Calculer les métriques
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

    # ROC-AUC multi-classe
    y_test_bin = label_binarize(
        y_test,
        classes=[0, 1, 2],
    )

    roc_auc = roc_auc_score(
        y_test_bin,
        y_proba,
        multi_class="ovr",
        average="weighted",
    )

    # 7. Afficher les résultats
    print("\n========== MODEL RESULTS ==========")

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    print(f"ROC-AUC   : {roc_auc:.4f}")

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            labels=[0, 1, 2],
            target_names=[
                "BENIGN",
                "DDoS",
                "PortScan",
            ],
            zero_division=0,
        )
    )

    # 8. Sauvegarder le modèle
    model_dir = "app/ml/models"

    os.makedirs(
        model_dir,
        exist_ok=True,
    )

    model_path = os.path.join(
        model_dir,
        "network_attack_random_forest.joblib",
    )

    joblib.dump(
        model,
        model_path,
    )

    print(
        f"\nModel saved to: {model_path}"
    )


if __name__ == "__main__":
    train_model()