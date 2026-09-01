from app.services.ioc_extractor import IOCExtractor


def test_file_name_is_not_extracted_as_domain():
    extractor = IOCExtractor()

    result = extractor.extract_all(
        "/etc/cups/subscriptions.conf.O"
    )

    assert result["domains"] == []


def test_valid_domain_is_extracted():
    extractor = IOCExtractor()

    result = extractor.extract_all(
        "Suspicious connection to evil.example.com detected"
    )

    assert "evil.example.com" in result["domains"]


def test_url_and_domain_are_extracted():
    extractor = IOCExtractor()

    result = extractor.extract_all(
        "Visit https://malware.example.com/payload"
    )

    assert "https://malware.example.com/payload" in result["urls"]
    assert "malware.example.com" in result["domains"]


def test_ipv4_is_extracted_without_domain_false_positive():
    extractor = IOCExtractor()

    result = extractor.extract_all(
        "Source IP 8.8.8.8"
    )

    assert "8.8.8.8" in result["ips"]
    assert result["domains"] == []
