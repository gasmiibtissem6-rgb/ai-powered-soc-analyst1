from unittest.mock import Mock

import pytest

from app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
)


def build_service(monkeypatch):
    monkeypatch.setattr(
        "app.services.threat_intelligence_service.secret_manager.get",
        lambda key: "test-api-key",
    )

    return ThreatIntelligenceService()


@pytest.mark.parametrize(
    ("score", "expected_risk"),
    [
        (0, "SAFE"),
        (24, "SAFE"),
        (25, "SUSPICIOUS"),
        (74, "SUSPICIOUS"),
        (75, "MALICIOUS"),
        (100, "MALICIOUS"),
    ],
)
def test_check_ip_maps_abuse_score_to_risk(
    monkeypatch,
    score,
    expected_risk,
):
    service = build_service(monkeypatch)

    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": score,
            "countryCode": "US",
            "isp": "Example ISP",
            "domain": "example.com",
            "isTor": False,
            "totalReports": 10,
        }
    }

    monkeypatch.setattr(
        "app.services.threat_intelligence_service.requests.get",
        lambda *args, **kwargs: response,
    )

    result = service.check_ip("8.8.8.8")

    assert result["ip_address"] == "8.8.8.8"
    assert result["risk"] == expected_risk
    assert result["abuse_score"] == score
    assert result["country"] == "US"
    assert result["isp"] == "Example ISP"
    assert result["domain"] == "example.com"
    assert result["is_tor"] is False
    assert result["total_reports"] == 10


def test_extract_ips(monkeypatch):
    service = build_service(monkeypatch)

    result = service.extract_ips(
        "Connections from 8.8.8.8 and 1.1.1.1 detected."
    )

    assert set(result) == {
        "8.8.8.8",
        "1.1.1.1",
    }


def test_extract_ips_removes_duplicates(monkeypatch):
    service = build_service(monkeypatch)

    result = service.extract_ips(
        "8.8.8.8 contacted 8.8.8.8"
    )

    assert result == ["8.8.8.8"]


def test_analyze_text(monkeypatch):
    service = build_service(monkeypatch)

    monkeypatch.setattr(
        service,
        "check_ip",
        lambda ip: {
            "ip_address": ip,
            "risk": "SAFE",
        },
    )

    result = service.analyze_text(
        "Observed traffic from 8.8.8.8"
    )

    assert result == [
        {
            "ip_address": "8.8.8.8",
            "risk": "SAFE",
        }
    ]


def test_analyze_text_handles_provider_failure(monkeypatch):
    service = build_service(monkeypatch)

    def fail_check(ip):
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(
        service,
        "check_ip",
        fail_check,
    )

    result = service.analyze_text(
        "Observed traffic from 8.8.8.8"
    )

    assert result == [
        {
            "ip_address": "8.8.8.8",
            "error": "Threat intelligence analysis failed",
        }
    ]
