from typing import Dict

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
    Predict network traffic as BENIGN, DDoS or PortScan.
    """

    try:
        result = predict_traffic(request.features)

        return {
            "status": "success",
            "prediction": result["prediction"],
            "benign_probability": result["benign_probability"],
            "ddos_probability": result["ddos_probability"],
            "portscan_probability": result["portscan_probability"],
        }

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Prediction failed: {str(e)}",
        )