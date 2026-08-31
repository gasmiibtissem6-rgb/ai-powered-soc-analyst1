import ipaddress
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse


class IOCExtractor:
    """
    Extract Indicators of Compromise (IOCs) from text.

    Supported IOC types:
    - IPv4
    - Domain
    - URL
    - File hash: MD5, SHA1, SHA256
    """

    IPV4_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    URL_PATTERN = re.compile(
        r"https?://[^\s\"'<>]+",
        re.IGNORECASE,
    )

    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b"
    )

    MD5_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    )

    SHA1_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    )

    SHA256_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    )

    # =====================================================
    # IP ADDRESSES
    # =====================================================

    def extract_ips(self, text: str) -> List[str]:
        candidates = self.IPV4_PATTERN.findall(text or "")
        valid_ips = set()

        for candidate in candidates:
            try:
                ipaddress.ip_address(candidate)
                valid_ips.add(candidate)
            except ValueError:
                continue

        return sorted(valid_ips)

    # =====================================================
    # URLS
    # =====================================================

    def extract_urls(self, text: str) -> List[str]:
        urls = set()

        for match in self.URL_PATTERN.findall(text or ""):
            cleaned = match.rstrip(".,);]}")
            urls.add(cleaned)

        return sorted(urls)

    # =====================================================
    # DOMAINS
    # =====================================================

    def extract_domains(
        self,
        text: str,
        urls: Optional[List[str]] = None,
    ) -> List[str]:

        domains = set(
            self.DOMAIN_PATTERN.findall(text or "")
        )

        # Add domains extracted from URLs
        for url in urls or []:
            try:
                parsed = urlparse(url)

                if parsed.hostname:
                    domains.add(
                        parsed.hostname.lower()
                    )

            except Exception:
                continue

        # Remove IP addresses accidentally matched as domains
        valid_domains = set()

        for domain in domains:
            try:
                ipaddress.ip_address(domain)
                continue
            except ValueError:
                pass

            valid_domains.add(
                domain.lower()
            )

        return sorted(valid_domains)

    # =====================================================
    # HASHES
    # =====================================================

    def extract_hashes(self, text: str) -> List[Dict[str, str]]:
        text = text or ""

        hashes = []
        seen = set()

        patterns = [
            ("md5", self.MD5_PATTERN),
            ("sha1", self.SHA1_PATTERN),
            ("sha256", self.SHA256_PATTERN),
        ]

        for hash_type, pattern in patterns:
            for value in pattern.findall(text):

                normalized = value.lower()

                if normalized in seen:
                    continue

                seen.add(normalized)

                hashes.append(
                    {
                        "hash_type": hash_type,
                        "value": normalized,
                    }
                )

        return hashes

    # =====================================================
    # EXTRACT ALL
    # =====================================================

    def extract_all(self, text: str) -> dict:
        urls = self.extract_urls(text)

        return {
            "ips": self.extract_ips(text),
            "domains": self.extract_domains(
                text,
                urls=urls,
            ),
            "urls": urls,
            "hashes": self.extract_hashes(text),
        }