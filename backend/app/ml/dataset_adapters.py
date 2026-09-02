from pathlib import Path
from typing import Dict, List

import pandas as pd


CSE_CIC_IDS2018_TO_CICIDS2017 = {
    "Dst Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}


class DatasetAdapter:
    """
    Normalizes external intrusion-detection datasets
    before model training or evaluation.
    """

    def __init__(self, dataset_name: str):
        self.dataset_name = dataset_name.lower()

    def load(self, path: str) -> pd.DataFrame:
        dataset_path = Path(path)

        if not dataset_path.exists():
            raise FileNotFoundError(
                f"Dataset not found: {dataset_path}"
            )

        df = pd.read_csv(
    dataset_path,
    low_memory=False,
)

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

        # Remove repeated header rows present in some
        # official CSV files.
        result = result[
            result["Label"].str.lower() != "label"
        ].copy()

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

    @staticmethod
    def align_cse_cic_ids2018_to_cicids2017(
        df: pd.DataFrame,
        reference_features: List[str],
    ) -> pd.DataFrame:
        """
        Align CSE-CIC-IDS2018 CICFlowMeter columns
        with the CICIDS2017 feature schema.

        CSE-CIC-IDS2018 contains Protocol while the
        CICIDS2017 CSV used by this project contains
        the duplicated Fwd Header Length.1 feature.
        """

        result = df.copy()

        result.rename(
            columns=CSE_CIC_IDS2018_TO_CICIDS2017,
            inplace=True,
        )

        # Timestamp is metadata, not a model feature.
        result.drop(
            columns=["Timestamp"],
            errors="ignore",
            inplace=True,
        )

        # Protocol does not exist in the project's
        # CICIDS2017 model schema.
        result.drop(
            columns=["Protocol"],
            errors="ignore",
            inplace=True,
        )

        # CICIDS2017 contains this duplicated feature.
        if (
            "Fwd Header Length" in result.columns
            and "Fwd Header Length.1" not in result.columns
        ):
            result["Fwd Header Length.1"] = (
                result["Fwd Header Length"]
            )

        missing = [
            feature
            for feature in reference_features
            if feature not in result.columns
        ]

        if missing:
            raise ValueError(
                "Missing CICIDS2017 features after "
                f"alignment: {missing}"
            )

        aligned = result[
            reference_features
        ].copy()

        return aligned

    @staticmethod
    def clean_numeric_features(
        df: pd.DataFrame,
    ) -> pd.DataFrame:
        """
        Convert model features to numeric values and
        remove rows containing NaN or infinite values.
        """

        result = df.copy()

        for column in result.columns:
            result[column] = pd.to_numeric(
                result[column],
                errors="coerce",
            )

        result.replace(
            [float("inf"), float("-inf")],
            float("nan"),
            inplace=True,
        )

        result.dropna(
            inplace=True,
        )

        result.reset_index(
            drop=True,
            inplace=True,
        )

        # Guarantee numeric dtypes after cleaning.
        result = result.astype("float64")

        return result


SUPPORTED_DATASETS: Dict[str, str] = {
    "cse-cic-ids2018": "CSE-CIC-IDS2018",
    "unsw-nb15": "UNSW-NB15",
}