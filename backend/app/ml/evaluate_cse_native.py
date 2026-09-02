from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

from app.ml.cse_preprocess import (
    load_cse_cic_ids2018,
    split_cse_cic_ids2018,
)


def evaluate_cse_native():
    X, y = load_cse_cic_ids2018()

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = split_cse_cic_ids2018(X, y)

    print("\n========== DATA SPLIT ==========")
    print("Training samples:", len(X_train))
    print("Testing samples :", len(X_test))
    print("Features        :", X.shape[1])

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    print("\nTraining CSE-CIC-IDS2018 Random Forest...")

    model.fit(
        X_train,
        y_train,
    )

    print("Training completed.")

    y_pred = model.predict(X_test)

    y_proba = model.predict_proba(
        X_test
    )[:, 1]

    accuracy = accuracy_score(
        y_test,
        y_pred,
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    roc_auc = roc_auc_score(
        y_test,
        y_proba,
    )

    print(
        "\n========== CSE-CIC-IDS2018 "
        "NATIVE EVALUATION =========="
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
            y_test,
            y_pred,
            labels=[0, 1],
            target_names=[
                "Benign",
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
        y_test,
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
    }


if __name__ == "__main__":
    evaluate_cse_native()
