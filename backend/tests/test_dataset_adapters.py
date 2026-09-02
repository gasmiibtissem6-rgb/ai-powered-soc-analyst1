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
def test_cse_cic_ids2018_alignment_and_cleaning():
    reference_features = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Fwd Header Length",
        "Fwd Header Length.1",
        "Flow Bytes/s",
        "Flow Packets/s",
    ]

    df = pd.DataFrame(
        {
            "Dst Port": [80, 443, 22],
            "Flow Duration": [1000, 2000, 3000],
            "Tot Fwd Pkts": [10, 20, 30],
            "Fwd Header Len": [32, 40, 48],
            "Flow Byts/s": [
                "100.5",
                "Infinity",
                "300.5",
            ],
            "Flow Pkts/s": [
                "10.5",
                "20.5",
                "30.5",
            ],
            "Protocol": [6, 6, 6],
            "Timestamp": [
                "01/03/2018 10:00:00",
                "01/03/2018 10:00:01",
                "01/03/2018 10:00:02",
            ],
        }
    )

    aligned = (
        DatasetAdapter
        .align_cse_cic_ids2018_to_cicids2017(
            df,
            reference_features,
        )
    )

    cleaned = DatasetAdapter.clean_numeric_features(
        aligned
    )

    assert cleaned.columns.tolist() == reference_features
    assert cleaned.shape == (2, 7)
    assert cleaned.isna().sum().sum() == 0

    assert all(
        pd.api.types.is_numeric_dtype(dtype)
        for dtype in cleaned.dtypes
    )

    assert (
        cleaned["Fwd Header Length"]
        == cleaned["Fwd Header Length.1"]
    ).all()
