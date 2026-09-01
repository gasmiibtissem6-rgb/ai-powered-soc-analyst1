import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.core.ingestion_security import verify_ingestion_api_key


def test_ingestion_rejects_missing_key(monkeypatch):
    monkeypatch.setattr(
        settings,
        "SOC_INGESTION_API_KEY",
        "test-secret-key",
    )

    with pytest.raises(HTTPException) as exc:
        verify_ingestion_api_key(None)

    assert exc.value.status_code == 401
    assert exc.value.detail == "SOC ingestion API key required"


def test_ingestion_rejects_wrong_key(monkeypatch):
    monkeypatch.setattr(
        settings,
        "SOC_INGESTION_API_KEY",
        "test-secret-key",
    )

    with pytest.raises(HTTPException) as exc:
        verify_ingestion_api_key("wrong-key")

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid SOC ingestion API key"


def test_ingestion_accepts_correct_key(monkeypatch):
    monkeypatch.setattr(
        settings,
        "SOC_INGESTION_API_KEY",
        "test-secret-key",
    )

    result = verify_ingestion_api_key(
        "test-secret-key"
    )

    assert result is None


def test_ingestion_returns_503_when_not_configured(monkeypatch):
    monkeypatch.setattr(
        settings,
        "SOC_INGESTION_API_KEY",
        "",
    )

    with pytest.raises(HTTPException) as exc:
        verify_ingestion_api_key("any-key")

    assert exc.value.status_code == 503
    assert (
        exc.value.detail
        == "SOC ingestion authentication is not configured"
    )
