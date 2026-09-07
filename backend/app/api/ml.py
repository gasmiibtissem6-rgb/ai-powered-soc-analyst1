from typing import Dict

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel

from app.core.security import require_analyst
from app.ml.predictor import predict_traffic
from app.models.user import User
from app.services.ml_service import MLService


router = APIRouter(
    prefix="/ml",
    tags=["Machine Learning"],
)


class TrafficPredictionRequest(BaseModel):
    features: Dict[str, float]


@router.post("/predict")
def predict_network_traffic(
    request: TrafficPredictionRequest,
    current_user: User = Depends(require_analyst),
):
    """
    Predict network traffic as:
    BENIGN, DDoS, PortScan, FTP-Patator or SSH-Patator.
    """

    try:
        result = predict_traffic(
            request.features
        )

        return {
            "status": "success",
            "prediction": result[
                "prediction"
            ],
            "benign_probability": result[
                "benign_probability"
            ],
            "ddos_probability": result[
                "ddos_probability"
            ],
            "portscan_probability": result[
                "portscan_probability"
            ],
            "ftp_patator_probability": result[
                "ftp_patator_probability"
            ],
            "ssh_patator_probability": result[
                "ssh_patator_probability"
            ],
        }

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Prediction failed",
        )


@router.post("/suricata-anomaly")
def predict_suricata_flow_anomaly(
    event: Dict,
    current_user: User = Depends(require_analyst),
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

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Suricata anomaly prediction failed",
        )
