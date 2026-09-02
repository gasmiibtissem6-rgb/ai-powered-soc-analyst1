from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
)
from sklearn.pipeline import Pipeline

from app.ml.unsw_preprocess import (
    build_unsw_preprocessor,
    load_unsw_nb15,
    split_unsw_nb15,
)


def evaluate_unsw():
    X, y = load_unsw_nb15()

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = split_unsw_nb15(X, y)

    print("\n========== DATA SPLIT ==========")
    print("Training samples:", len(X_train))
    print("Testing samples :", len(X_test))
    print("Features        :", X.shape[1])

    preprocessor = build_unsw_preprocessor(X_train)

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", model),
        ]
    )

    print("\nTraining Random Forest...")

    pipeline.fit(
        X_train,
        y_train,
    )

    print("Training completed.")

    predictions = pipeline.predict(X_test)

    probabilities = pipeline.predict_proba(
        X_test
    )[:, 1]

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    roc_auc = roc_auc_score(
        y_test,
        probabilities,
    )

    print("\n========== UNSW-NB15 RESULTS ==========")

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"ROC-AUC  : {roc_auc:.4f}")

    print("\n========== CLASSIFICATION REPORT ==========")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Normal",
                "Attack",
            ],
            digits=4,
            zero_division=0,
        )
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
    }


if __name__ == "__main__":
    evaluate_unsw()
