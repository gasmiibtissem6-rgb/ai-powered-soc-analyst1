from typing import Dict
from app.services.ml_service import MLService
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.ml.predictor import predict_traffic


router = APIRouter(
    prefix="/ml",
    tags=["Machine Learning"],
)


class TrafficPredictionRequest(BaseModel):
    features: Dict[str, float]


@router.post("/predict")
def predict_network_traffic(request: TrafficPredictionRequest):
    """
    Predict network traffic as:
    BENIGN, DDoS, PortScan, FTP-Patator or SSH-Patator.
    """

    try:
        result = predict_traffic(request.features)

        return {
            "status": "success",
            "prediction": result["prediction"],
            "benign_probability": result["benign_probability"],
            "ddos_probability": result["ddos_probability"],
            "portscan_probability": result["portscan_probability"],
            "ftp_patator_probability": result["ftp_patator_probability"],
            "ssh_patator_probability": result["ssh_patator_probability"],
        }

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Prediction failed: {str(e)}",
        )
@router.post("/suricata-anomaly")
def predict_suricata_flow_anomaly(
    event: Dict,
):
    """
    Detect anomalous Suricata flow events
    using Isolation Forest.
    """

    try:
        service = MLService()

        result = (
            service.detect_suricata_anomaly(
                event
            )
        )

        return {
            "status": result["status"],
            "prediction": result["prediction"],
            "is_anomaly": result["is_anomaly"],
            "anomaly_score": result[
                "anomaly_score"
            ],
            "features": result["features"],
        }

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Suricata anomaly prediction "
                f"failed: {str(exc)}"
            ),
        )
