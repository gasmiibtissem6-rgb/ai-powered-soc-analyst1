from pathlib import Path
from typing import Dict

import pandas as pd


class DatasetAdapter:
    """
    Normalizes external intrusion-detection datasets
    before model training/evaluation.
    """

    def __init__(self, dataset_name: str):
        self.dataset_name = dataset_name.lower()

    def load(self, path: str) -> pd.DataFrame:
        dataset_path = Path(path)

        if not dataset_path.exists():
            raise FileNotFoundError(
                f"Dataset not found: {dataset_path}"
            )

        df = pd.read_csv(dataset_path)

        df.columns = (
            df.columns
            .astype(str)
            .str.strip()
        )

        return df

    def normalize_labels(
        self,
        df: pd.DataFrame,
    ) -> pd.DataFrame:
        if self.dataset_name == "cse-cic-ids2018":
            return self._normalize_cse_cic_ids2018(df)

        if self.dataset_name == "unsw-nb15":
            return self._normalize_unsw_nb15(df)

        raise ValueError(
            f"Unsupported dataset: {self.dataset_name}"
        )

    @staticmethod
    def _normalize_cse_cic_ids2018(
        df: pd.DataFrame,
    ) -> pd.DataFrame:
        if "Label" not in df.columns:
            raise ValueError(
                "CSE-CIC-IDS2018 dataset must contain "
                "a 'Label' column."
            )

        result = df.copy()

        result["Label"] = (
            result["Label"]
            .astype(str)
            .str.strip()
        )

        return result

    @staticmethod
    def _normalize_unsw_nb15(
        df: pd.DataFrame,
    ) -> pd.DataFrame:
        result = df.copy()

        label_candidates = [
            "label",
            "Label",
            "attack_cat",
        ]

        label_column = None

        for candidate in label_candidates:
            if candidate in result.columns:
                label_column = candidate
                break

        if label_column is None:
            raise ValueError(
                "UNSW-NB15 dataset does not contain "
                "a supported label column."
            )

        result[label_column] = (
            result[label_column]
            .astype(str)
            .str.strip()
        )

        if label_column != "Label":
            result.rename(
                columns={
                    label_column: "Label",
                },
                inplace=True,
            )

        return result


SUPPORTED_DATASETS: Dict[str, str] = {
    "cse-cic-ids2018": (
        "CSE-CIC-IDS2018"
    ),
    "unsw-nb15": (
        "UNSW-NB15"
    ),
}
