import secrets
from typing import Optional

from fastapi import Header, HTTPException, status

from app.core.config import settings
from app.core.secrets import secret_manager

def verify_ingestion_api_key(
    x_soc_ingestion_key: Optional[str] = Header(
        None,
        alias="X-SOC-Ingestion-Key",
    ),
) -> None:
    """
    Authenticate trusted machine-to-machine ingestion
    requests coming from Wazuh and Suricata forwarders.
    """

    expected_key = secret_manager.get("SOC_INGESTION_API_KEY")

    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOC ingestion authentication is not configured",
        )

    if not x_soc_ingestion_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SOC ingestion API key required",
        )

    if not secrets.compare_digest(
        x_soc_ingestion_key,
        expected_key,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SOC ingestion API key",
        )