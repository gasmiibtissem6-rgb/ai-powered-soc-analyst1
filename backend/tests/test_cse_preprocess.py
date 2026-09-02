import pandas as pd

from app.ml.cse_preprocess import split_cse_cic_ids2018


def test_cse_split_preserves_binary_classes():
    X = pd.DataFrame(
        {
            "feature_1": list(range(20)),
            "feature_2": list(range(100, 120)),
        }
    )

    y = pd.Series(
        [0] * 10 + [1] * 10
    )

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = split_cse_cic_ids2018(X, y)

    assert len(X_train) == 16
    assert len(X_test) == 4

    assert len(y_train) == 16
    assert len(y_test) == 4

    assert set(y_train.unique()) == {0, 1}
    assert set(y_test.unique()) == {0, 1}


def test_cse_split_has_no_overlap():
    X = pd.DataFrame(
        {
            "feature_1": list(range(100)),
            "feature_2": list(range(100, 200)),
        }
    )

    y = pd.Series(
        [0] * 50 + [1] * 50
    )

    (
        X_train,
        X_test,
        _,
        _,
    ) = split_cse_cic_ids2018(X, y)

    train_rows = {
        tuple(row)
        for row in X_train.to_numpy()
    }

    test_rows = {
        tuple(row)
        for row in X_test.to_numpy()
    }

    assert train_rows.isdisjoint(test_rows)
