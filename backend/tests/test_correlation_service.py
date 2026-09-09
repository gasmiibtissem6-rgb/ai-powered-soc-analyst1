from app.services.correlation_service import CorrelationService


# =========================================================
# BROAD ACTIVITY CLASSIFICATION
# =========================================================


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


# =========================================================
# DETAILED ATTACK TYPE CLASSIFICATION
# =========================================================


def test_classify_attack_type_brute_force():
    result = CorrelationService.classify_attack_type(
        "SSH brute force detected",
        "Multiple failed password attempts",
    )

    assert result == "brute_force"


def test_classify_attack_type_credential_stuffing():
    result = CorrelationService.classify_attack_type(
        "Credential stuffing attack",
        "Stolen credentials reused against accounts",
    )

    assert result == "credential_stuffing"


def test_classify_attack_type_password_spraying():
    result = CorrelationService.classify_attack_type(
        "Password spraying detected",
        "Password spray against multiple accounts",
    )

    assert result == "password_spraying"


def test_classify_attack_type_sql_injection():
    result = CorrelationService.classify_attack_type(
        "SQL injection attempt",
        "Suspicious UNION SELECT payload",
    )

    assert result == "sql_injection"


def test_classify_attack_type_xss():
    result = CorrelationService.classify_attack_type(
        "Cross-site scripting detected",
        "Reflected XSS payload",
    )

    assert result == "xss"


def test_classify_attack_type_rce():
    result = CorrelationService.classify_attack_type(
        "Remote code execution detected",
        "Command injection against web service",
    )

    assert result == "rce"


def test_classify_attack_type_malware():
    result = CorrelationService.classify_attack_type(
        "Malware detected",
        "Trojan activity observed on endpoint",
    )

    assert result == "malware"


def test_classify_attack_type_ransomware():
    result = CorrelationService.classify_attack_type(
        "Ransomware detected",
        "Mass encryption of files observed",
    )

    assert result == "ransomware"


def test_classify_attack_type_port_scan():
    result = CorrelationService.classify_attack_type(
        "Nmap port scan detected",
        "TCP SYN scan against multiple ports",
    )

    assert result == "port_scan"


def test_classify_attack_type_ddos():
    result = CorrelationService.classify_attack_type(
        "DDoS attack detected",
        "Distributed denial of service traffic",
    )

    assert result == "ddos"


def test_classify_attack_type_privilege_escalation():
    result = CorrelationService.classify_attack_type(
        "Privilege escalation detected",
        "Elevation of privilege on endpoint",
    )

    assert result == "privilege_escalation"


def test_classify_attack_type_lateral_movement():
    result = CorrelationService.classify_attack_type(
        "Lateral movement detected",
        "Remote service movement between hosts",
    )

    assert result == "lateral_movement"


def test_classify_attack_type_data_exfiltration():
    result = CorrelationService.classify_attack_type(
        "Data exfiltration detected",
        "Large data exfil transfer observed",
    )

    assert result == "data_exfiltration"


def test_classify_attack_type_insider_threat():
    result = CorrelationService.classify_attack_type(
        "Insider threat detected",
        "Malicious insider accessed sensitive resources",
    )

    assert result == "insider_threat"


def test_classify_attack_type_command_and_control():
    result = CorrelationService.classify_attack_type(
        "Command and control traffic detected",
        "C2 beacon communication observed",
    )

    assert result == "command_and_control"


def test_classify_attack_type_unknown():
    result = CorrelationService.classify_attack_type(
        "Security event",
        "Unclassified suspicious activity",
    )

    assert result == "unknown"


# =========================================================
# CORRELATION ID
# =========================================================


def test_generate_correlation_id():
    correlation_id = (
        CorrelationService.generate_correlation_id()
    )

    assert correlation_id.startswith("SOC-")
    assert len(correlation_id) > 4


# =========================================================
# MULTI-SOURCE CORRELATION SUMMARY
# =========================================================


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