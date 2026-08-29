from sklearn.model_selection import train_test_split

from app.ml.preprocess import load_and_preprocess_data


def check_leakage():
    print("Loading data...")

    X, y = load_and_preprocess_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("\nTrain shape:", X_train.shape)
    print("Test shape :", X_test.shape)

    # Vérifier les doublons dans tout le dataset
    full_duplicates = X.duplicated().sum()

    print("\nDuplicate feature rows in full dataset:", full_duplicates)

    # Vérifier si des lignes du test existent aussi dans le train
    train_hashes = set(
        X_train.astype(str).agg("|".join, axis=1)
    )

    test_hashes = X_test.astype(str).agg("|".join, axis=1)

    overlap = test_hashes.isin(train_hashes).sum()

    print("Test rows also present in training set:", overlap)

    if overlap == 0:
        print("\nOK: no exact duplicate leakage detected.")
    else:
        print(
            "\nWARNING: duplicate rows exist between train and test."
        )


if __name__ == "__main__":
    check_leakage()