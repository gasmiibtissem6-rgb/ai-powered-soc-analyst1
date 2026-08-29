from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate

from app.ml.preprocess import load_and_preprocess_data


def run_cross_validation():
    print("Loading and preprocessing data...")

    X, y = load_and_preprocess_data()

    print("\n========== CROSS VALIDATION ==========")
    print("Samples :", len(X))
    print("Features:", X.shape[1])

    # 5-fold stratified cross-validation
    cv = StratifiedKFold(
        n_splits=5,
        shuffle=True,
        random_state=42,
    )

    # Même modèle que celui utilisé dans train_model.py
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    print("\nRunning 5-fold cross-validation...")
    print("This may take a few minutes.\n")

    scoring = {
        "accuracy": "accuracy",
        "precision": "precision_weighted",
        "recall": "recall_weighted",
        "f1": "f1_weighted",
        "roc_auc": "roc_auc_ovr_weighted",
    }

    results = cross_validate(
        model,
        X,
        y,
        cv=cv,
        scoring=scoring,
        n_jobs=1,
        return_train_score=False,
    )

    print("========== CROSS-VALIDATION RESULTS ==========")

    metrics = [
        ("Accuracy", "test_accuracy"),
        ("Precision", "test_precision"),
        ("Recall", "test_recall"),
        ("F1 Score", "test_f1"),
        ("ROC-AUC", "test_roc_auc"),
    ]

    for name, key in metrics:
        scores = results[key]

        print(f"\n{name}:")
        for i, score in enumerate(scores, start=1):
            print(f"  Fold {i}: {score:.4f}")

        print(f"  Mean  : {scores.mean():.4f}")
        print(f"  Std   : {scores.std():.4f}")

    print("\nCross-validation completed.")


if __name__ == "__main__":
    run_cross_validation()