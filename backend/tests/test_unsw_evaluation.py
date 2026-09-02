import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from app.ml.unsw_preprocess import build_unsw_preprocessor


def test_unsw_model_pipeline():
    X = pd.DataFrame(
        {
            "dur": [
                0.1, 0.2, 0.3, 0.4,
                1.1, 1.2, 1.3, 1.4,
            ],
            "spkts": [
                2, 3, 2, 4,
                50, 60, 55, 70,
            ],
            "proto": [
                "tcp", "tcp", "udp", "tcp",
                "udp", "udp", "tcp", "udp",
            ],
            "service": [
                "http", "http", "dns", "http",
                "dns", "dns", "ftp", "dns",
            ],
            "state": [
                "FIN", "FIN", "CON", "FIN",
                "CON", "CON", "INT", "CON",
            ],
        }
    )

    y = pd.Series(
        [0, 0, 0, 0, 1, 1, 1, 1]
    )

    preprocessor = build_unsw_preprocessor(X)

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=10,
                    random_state=42,
                ),
            ),
        ]
    )

    pipeline.fit(X, y)

    predictions = pipeline.predict(X)
    probabilities = pipeline.predict_proba(X)

    assert len(predictions) == len(X)
    assert probabilities.shape == (len(X), 2)
    assert set(predictions).issubset({0, 1})
