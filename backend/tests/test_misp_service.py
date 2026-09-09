from unittest.mock import Mock

import requests

from app.services.misp_service import MISPService


def test_misp_not_configured(monkeypatch):
    monkeypatch.setattr(
        "app.services.misp_service.settings.MISP_URL",
        "",
    )
    monkeypatch.setattr(
        "app.services.misp_service.secret_manager.get",
        lambda key: "",
    )

    service = MISPService()

    result = service.check_ip("8.8.8.8")

    assert result["provider"] == "MISP"
    assert result["status"] == "not_configured"
    assert result["risk"] == "UNKNOWN"
    assert result["match_count"] == 0
    assert result["matches"] == []


def test_misp_ip_match(monkeypatch):
    monkeypatch.setattr(
        "app.services.misp_service.settings.MISP_URL",
        "https://misp.example.local",
    )
    monkeypatch.setattr(
        "app.services.misp_service.secret_manager.get",
        lambda key: "test-api-key",
    )

    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "response": {
            "Attribute": [
                {
                    "id": "10",
                    "type": "ip-dst",
                    "category": "Network activity",
                    "value": "8.8.8.8",
                    "comment": "Test IOC",
                    "event_id": "42",
                    "Event": {
                        "info": "Malicious infrastructure"
                    },
                }
            ]
        }
    }

    monkeypatch.setattr(
        "app.services.misp_service.requests.post",
        lambda *args, **kwargs: response,
    )

    service = MISPService()

    result = service.check_ip("8.8.8.8")

    assert result["status"] == "success"
    assert result["risk"] == "SUSPICIOUS"
    assert result["match_count"] == 1
    assert result["matches"][0]["id"] == "10"
    assert result["matches"][0]["value"] == "8.8.8.8"
    assert result["matches"][0]["event_info"] == (
        "Malicious infrastructure"
    )


def test_misp_no_match(monkeypatch):
    monkeypatch.setattr(
        "app.services.misp_service.settings.MISP_URL",
        "https://misp.example.local",
    )
    monkeypatch.setattr(
        "app.services.misp_service.secret_manager.get",
        lambda key: "test-api-key",
    )

    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "response": {
            "Attribute": []
        }
    }

    monkeypatch.setattr(
        "app.services.misp_service.requests.post",
        lambda *args, **kwargs: response,
    )

    service = MISPService()

    result = service.check_domain("example.com")

    assert result["status"] == "success"
    assert result["risk"] == "SAFE"
    assert result["match_count"] == 0
    assert result["matches"] == []


def test_misp_timeout(monkeypatch):
    monkeypatch.setattr(
        "app.services.misp_service.settings.MISP_URL",
        "https://misp.example.local",
    )
    monkeypatch.setattr(
        "app.services.misp_service.secret_manager.get",
        lambda key: "test-api-key",
    )

    def raise_timeout(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(
        "app.services.misp_service.requests.post",
        raise_timeout,
    )

    service = MISPService()

    try:
        service.check_url("https://example.com")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == "MISP request timed out."


def test_misp_request_failure(monkeypatch):
    monkeypatch.setattr(
        "app.services.misp_service.settings.MISP_URL",
        "https://misp.example.local",
    )
    monkeypatch.setattr(
        "app.services.misp_service.secret_manager.get",
        lambda key: "test-api-key",
    )

    def raise_request_error(*args, **kwargs):
        raise requests.RequestException()

    monkeypatch.setattr(
        "app.services.misp_service.requests.post",
        raise_request_error,
    )

    service = MISPService()

    try:
        service.check_hash(
            "44d88612fea8a8f36de82e1278abb02f"
        )
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == "MISP request failed."

