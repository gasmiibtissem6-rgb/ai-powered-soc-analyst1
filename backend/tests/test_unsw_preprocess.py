import pandas as pd

from app.ml.unsw_preprocess import (
    build_unsw_preprocessor,
    load_unsw_nb15,
    split_unsw_nb15,
)


def test_load_unsw_nb15(tmp_path):
    data = pd.DataFrame(
        {
            "id": [1, 2, 3],
            "dur": [1.0, 1.0, 2.0],
            "proto": ["tcp", "tcp", "udp"],
            "service": ["http", "http", "dns"],
            "state": ["FIN", "FIN", "CON"],
            "attack_cat": [
                "Normal",
                "Normal",
                "Generic",
            ],
            "label": [0, 0, 1],
        }
    )

    path = tmp_path / "unsw.csv"
    data.to_csv(path, index=False)

    X, y = load_unsw_nb15(str(path))

    # Rows 1 and 2 are duplicates when id is ignored.
    assert len(X) == 2
    assert len(y) == 2

    assert "id" not in X.columns
    assert "attack_cat" not in X.columns
    assert "label" not in X.columns

    assert set(y.tolist()) == {0, 1}


def test_split_unsw_nb15():
    X = pd.DataFrame(
        {
            "dur": list(range(20)),
            "proto": ["tcp"] * 10 + ["udp"] * 10,
            "service": ["http"] * 20,
            "state": ["FIN"] * 20,
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
    ) = split_unsw_nb15(X, y)

    assert len(X_train) == 16
    assert len(X_test) == 4
    assert len(y_train) == 16
    assert len(y_test) == 4

    assert set(y_train.unique()) == {0, 1}
    assert set(y_test.unique()) == {0, 1}


def test_unsw_preprocessor_handles_categories():
    X = pd.DataFrame(
        {
            "dur": [0.1, 0.2, 0.3],
            "spkts": [1, 2, 3],
            "proto": ["tcp", "udp", "tcp"],
            "service": ["http", "dns", "http"],
            "state": ["FIN", "CON", "FIN"],
        }
    )

    preprocessor = build_unsw_preprocessor(X)

    transformed = preprocessor.fit_transform(X)

    assert transformed.shape[0] == 3
    assert transformed.shape[1] > X.shape[1]
