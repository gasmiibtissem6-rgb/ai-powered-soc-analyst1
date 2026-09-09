import pytest

from app.services.otx_service import OTXService


def build_service(monkeypatch):
    monkeypatch.setattr(
        "app.services.otx_service.secret_manager.get",
        lambda key: "test-api-key",
    )

    return OTXService()


@pytest.mark.parametrize(
    ("ioc_type", "pulse_count", "expected_risk"),
    [
        ("ip", 0, "SAFE"),
        ("domain", 0, "SAFE"),
        ("url", 0, "SAFE"),
        ("hash", 0, "SAFE"),
        ("ip", 1, "SUSPICIOUS"),
        ("domain", 10, "SUSPICIOUS"),
        ("url", 5, "SUSPICIOUS"),
        ("hash", 1, "SUSPICIOUS"),
        ("hash", 4, "SUSPICIOUS"),
        ("hash", 5, "MALICIOUS"),
        ("hash", 20, "MALICIOUS"),
    ],
)
def test_calculate_risk(
    ioc_type,
    pulse_count,
    expected_risk,
):
    assert (
        OTXService._calculate_risk(
            ioc_type,
            pulse_count,
        )
        == expected_risk
    )


def fake_response():
    return {
        "pulse_info": {
            "count": 5,
            "pulses": [
                {
                    "name": "Test Pulse",
                    "id": "pulse-1",
                }
            ],
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

    assert result["provider"] == "AlienVault OTX"
    assert result["ioc_type"] == expected_type
    assert result["value"] == value
    assert result["pulse_count"] == 5
    assert result["pulses"] == [
        {
            "name": "Test Pulse",
            "id": "pulse-1",
        }
    ]

    if expected_type == "hash":
        assert result["risk"] == "MALICIOUS"
    else:
        assert result["risk"] == "SUSPICIOUS"


def test_request_fails_without_api_key(monkeypatch):
    monkeypatch.setattr(
        "app.services.otx_service.secret_manager.get",
        lambda key: "",
    )

    service = OTXService()

    with pytest.raises(
        RuntimeError,
        match="OTX_API_KEY is not configured",
    ):
        service._request("IPv4/8.8.8.8/general")


def test_request_retries_on_timeout(monkeypatch):
    service = build_service(monkeypatch)

    calls = {"count": 0}

    def timeout_request(*args, **kwargs):
        calls["count"] += 1
        raise __import__("requests").Timeout()

    monkeypatch.setattr(
        "app.services.otx_service.requests.get",
        timeout_request,
    )

    monkeypatch.setattr(
        "app.services.otx_service.time.sleep",
        lambda seconds: None,
    )

    with pytest.raises(
        RuntimeError,
        match="timed out after 2 attempts",
    ):
        service._request("IPv4/8.8.8.8/general")

    assert calls["count"] == 2
