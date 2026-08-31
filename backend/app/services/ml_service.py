from app.ml.predictor import predict_traffic
from app.ml.xgboost_predictor import (
    predict_traffic_xgboost,
)
from app.ml.suricata_anomaly_predictor import (
    predict_suricata_anomaly,
)


class MLService:
    """
    Service responsible for Machine Learning analysis.

    It supports:
    1. Supervised network traffic classification
       using the CICIDS2017 Random Forest model.
    2. Supervised network traffic classification
       using the CICIDS2017 XGBoost model.
    3. Unsupervised Suricata flow anomaly detection
       using Isolation Forest.
    """

    def predict_network_attack(
        self,
        features: dict,
    ):
        """
        Predict the network traffic class using
        the trained Random Forest model.
        """

        result = predict_traffic(
            features
        )

        return {
            "prediction": (
                result["prediction"]
            ),
            "benign_probability": (
                result[
                    "benign_probability"
                ]
            ),
            "ddos_probability": (
                result[
                    "ddos_probability"
                ]
            ),
            "portscan_probability": (
                result[
                    "portscan_probability"
                ]
            ),
            "ftp_patator_probability": (
                result[
                    "ftp_patator_probability"
                ]
            ),
            "ssh_patator_probability": (
                result[
                    "ssh_patator_probability"
                ]
            ),
        }

    def predict_network_attack_xgboost(
        self,
        features: dict,
    ):
        """
        Predict the network traffic class using
        the trained XGBoost model.
        """

        result = predict_traffic_xgboost(
            features
        )

        return {
            "prediction": (
                result["prediction"]
            ),
            "benign_probability": (
                result[
                    "benign_probability"
                ]
            ),
            "ddos_probability": (
                result[
                    "ddos_probability"
                ]
            ),
            "portscan_probability": (
                result[
                    "portscan_probability"
                ]
            ),
            "ftp_patator_probability": (
                result[
                    "ftp_patator_probability"
                ]
            ),
            "ssh_patator_probability": (
                result[
                    "ssh_patator_probability"
                ]
            ),
        }

    def detect_suricata_anomaly(
        self,
        event: dict,
    ):
        """
        Detect anomalous Suricata network flows
        using the trained Isolation Forest model.
        """

        result = predict_suricata_anomaly(
            event
        )

        return {
            "status": result[
                "status"
            ],
            "prediction": result[
                "prediction"
            ],
            "is_anomaly": result[
                "is_anomaly"
            ],
            "anomaly_score": result[
                "anomaly_score"
            ],
            "features": result[
                "features"
            ],
        }