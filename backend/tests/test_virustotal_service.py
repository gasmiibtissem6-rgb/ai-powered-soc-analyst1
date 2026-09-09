import pytest

from app.services.virustotal_service import VirusTotalService


def build_service(monkeypatch):
    monkeypatch.setattr(
        "app.services.virustotal_service.secret_manager.get",
        lambda key: "test-api-key",
    )

    return VirusTotalService()


@pytest.mark.parametrize(
    ("stats", "expected_risk"),
    [
        ({}, "SAFE"),
        ({"malicious": 0, "suspicious": 0}, "SAFE"),
        ({"malicious": 0, "suspicious": 1}, "SUSPICIOUS"),
        ({"malicious": 1, "suspicious": 0}, "SUSPICIOUS"),
        ({"malicious": 4, "suspicious": 0}, "SUSPICIOUS"),
        ({"malicious": 5, "suspicious": 0}, "MALICIOUS"),
        ({"malicious": 20, "suspicious": 3}, "MALICIOUS"),
    ],
)
def test_calculate_risk(
    stats,
    expected_risk,
):
    assert (
        VirusTotalService._calculate_risk(stats)
        == expected_risk
    )


def fake_response():
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 20,
                    "undetected": 30,
                },
                "reputation": -10,
            }
        }
    }


@pytest.mark.parametrize(
    ("method_name", "value", "expected_type"),
    [
        ("check_ip", "8.8.8.8", "ip"),
        ("check_domain", "example.com", "domain"),
        (
            "check_url",
            "https://example.com/test",
            "url",
        ),
        (
            "check_hash",
            "d41d8cd98f00b204e9800998ecf8427e",
            "hash",
        ),
    ],
)
def test_ioc_checks(
    monkeypatch,
    method_name,
    value,
    expected_type,
):
    service = build_service(monkeypatch)

    monkeypatch.setattr(
        service,
        "_request",
        lambda endpoint: fake_response(),
    )

    result = getattr(
        service,
        method_name,
    )(value)

    assert result["provider"] == "VirusTotal"
    assert result["ioc_type"] == expected_type
    assert result["value"] == value
    assert result["risk"] == "MALICIOUS"
    assert result["malicious"] == 5
    assert result["suspicious"] == 1
    assert result["harmless"] == 20
    assert result["undetected"] == 30
    assert result["reputation"] == -10


def test_request_fails_without_api_key(monkeypatch):
    monkeypatch.setattr(
        "app.services.virustotal_service.secret_manager.get",
        lambda key: "",
    )

    service = VirusTotalService()

    with pytest.raises(
        RuntimeError,
        match="VIRUSTOTAL_API_KEY is not configured",
    ):
        service._request("ip_addresses/8.8.8.8")
