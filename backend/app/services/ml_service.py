from app.ml.predictor import predict_traffic


class MLService:
    """
    Service responsible for Machine Learning
    network traffic classification.
    """

    def predict_network_attack(self, features: dict):
        """
        Predict the network traffic class using
        the trained Random Forest model.
        """

        result = predict_traffic(features)

        return {
            "prediction": result["prediction"],
            "benign_probability": result["benign_probability"],
            "ddos_probability": result["ddos_probability"],
            "portscan_probability": result["portscan_probability"],
            "ftp_patator_probability": result[
                "ftp_patator_probability"
            ],
            "ssh_patator_probability": result[
                "ssh_patator_probability"
            ],
        }