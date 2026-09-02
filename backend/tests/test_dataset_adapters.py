import pandas as pd
import pytest

from app.ml.dataset_adapters import DatasetAdapter


def test_cse_cic_ids2018_label_normalization():
    df = pd.DataFrame(
        {
            "Feature1": [1, 2],
            "Label": [" BENIGN ", "DDoS"],
        }
    )

    adapter = DatasetAdapter(
        "cse-cic-ids2018"
    )

    result = adapter.normalize_labels(df)

    assert result["Label"].tolist() == [
        "BENIGN",
        "DDoS",
    ]


def test_unsw_nb15_label_normalization():
    df = pd.DataFrame(
        {
            "feature1": [1, 2],
            "attack_cat": [
                " Normal ",
                "Exploits",
            ],
        }
    )

    adapter = DatasetAdapter(
        "unsw-nb15"
    )

    result = adapter.normalize_labels(df)

    assert "Label" in result.columns

    assert result["Label"].tolist() == [
        "Normal",
        "Exploits",
    ]


def test_unsupported_dataset():
    adapter = DatasetAdapter(
        "unknown-dataset"
    )

    df = pd.DataFrame(
        {
            "Label": ["BENIGN"],
        }
    )

    with pytest.raises(
        ValueError,
        match="Unsupported dataset",
    ):
        adapter.normalize_labels(df)
