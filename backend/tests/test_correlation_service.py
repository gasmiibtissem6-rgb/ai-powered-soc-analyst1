from app.services.correlation_service import CorrelationService


def test_classify_network_scan():
    result = CorrelationService.classify_activity(
        "Nmap TCP SYN port scan detected",
        "Network service discovery activity",
    )

    assert result == "network_scan"


def test_classify_authentication_attack():
    result = CorrelationService.classify_activity(
        "SSH brute force",
        "Multiple failed password attempts",
    )

    assert result == "authentication"


def test_classify_http_activity():
    result = CorrelationService.classify_activity(
        "Suspicious HTTP request",
        "Malicious URI detected",
    )

    assert result == "http"


def test_classify_malware_activity():
    result = CorrelationService.classify_activity(
        "Ransomware detected",
        "Malware activity on endpoint",
    )

    assert result == "malware"


def test_unknown_activity_is_generic():
    result = CorrelationService.classify_activity(
        "Security event",
        "Unclassified suspicious activity",
    )

    assert result == "generic"


def test_generate_correlation_id():
    correlation_id = (
        CorrelationService.generate_correlation_id()
    )

    assert correlation_id.startswith("SOC-")
    assert len(correlation_id) > 4


def test_correlation_summary_single_source():
    incident = {
        "source": "suricata",
        "correlation_id": "SOC-test-1",
    }

    result = (
        CorrelationService.build_correlation_summary(
            incident,
            [],
        )
    )

    assert result["source_count"] == 1
    assert result["sources"] == ["suricata"]
    assert result["confidence"] == "single_source"
    assert result["correlated_incident_count"] == 0


def test_correlation_summary_two_sources():
    incident = {
        "source": "suricata",
        "correlation_id": "SOC-test-2",
    }

    correlated = [
        {
            "source": "wazuh",
        }
    ]

    result = (
        CorrelationService.build_correlation_summary(
            incident,
            correlated,
        )
    )

    assert result["source_count"] == 2
    assert result["sources"] == [
        "suricata",
        "wazuh",
    ]
    assert result["confidence"] == "medium"
    assert result["correlated_incident_count"] == 1


def test_correlation_summary_three_sources():
    incident = {
        "source": "suricata",
        "correlation_id": "SOC-test-3",
    }

    correlated = [
        {"source": "wazuh"},
        {"source": "edr"},
    ]

    result = (
        CorrelationService.build_correlation_summary(
            incident,
            correlated,
        )
    )

    assert result["source_count"] == 3
    assert result["confidence"] == "high"
    assert result["correlated_incident_count"] == 2


def test_duplicate_source_does_not_increase_confidence():
    incident = {
        "source": "suricata",
        "correlation_id": "SOC-test-4",
    }

    correlated = [
        {"source": "suricata"},
        {"source": "suricata"},
    ]

    result = (
        CorrelationService.build_correlation_summary(
            incident,
            correlated,
        )
    )

    assert result["source_count"] == 1
    assert result["sources"] == ["suricata"]
    assert result["confidence"] == "single_source"
    assert result["correlated_incident_count"] == 2
