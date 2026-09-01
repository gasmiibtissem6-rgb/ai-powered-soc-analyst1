import ipaddress
import re
from typing import Dict, List, Optional
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

    # Common file extensions that can be falsely detected as TLDs.
    FILE_EXTENSIONS = {
        "conf",
        "config",
        "cfg",
        "ini",
        "log",
        "txt",
        "json",
        "xml",
        "yaml",
        "yml",
        "csv",
        "md",
        "py",
        "sh",
        "bash",
        "service",
        "socket",
        "pid",
        "lock",
        "bak",
        "old",
        "tmp",
        "swp",
        "db",
        "sqlite",
        "sql",
        "pem",
        "key",
        "crt",
        "cer",
    }

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

    def _is_valid_domain_candidate(self, domain: str) -> bool:
        """
        Validate a domain candidate extracted from free text.

        This filters common filenames such as:
        subscriptions.conf, application.log, config.yaml, etc.
        """

        domain = domain.lower().strip(".")

        if not domain or "." not in domain:
            return False

        # Reject IP addresses.
        try:
            ipaddress.ip_address(domain)
            return False
        except ValueError:
            pass

        labels = domain.split(".")

        if len(labels) < 2:
            return False

        # Domain labels cannot start or end with a hyphen.
        for label in labels:
            if not label:
                return False

            if label.startswith("-") or label.endswith("-"):
                return False

        suffix = labels[-1]

        # Avoid common filenames being interpreted as domains.
        if suffix in self.FILE_EXTENSIONS:
            return False

        return True

    def extract_domains(
        self,
        text: str,
        urls: Optional[List[str]] = None,
    ) -> List[str]:

        valid_domains = set()

        # Domains found directly in free text.
        for candidate in self.DOMAIN_PATTERN.findall(text or ""):
            domain = candidate.lower()

            if self._is_valid_domain_candidate(domain):
                valid_domains.add(domain)

        # Domains explicitly present inside URLs are trusted as URL hosts.
        # They are handled separately so a legitimate URL using an unusual
        # suffix is not discarded by the free-text filename filter.
        for url in urls or []:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname

                if not hostname:
                    continue

                hostname = hostname.lower()

                try:
                    ipaddress.ip_address(hostname)
                    continue
                except ValueError:
                    pass

                if self.DOMAIN_PATTERN.fullmatch(hostname):
                    valid_domains.add(hostname)

            except (ValueError, TypeError):
                continue

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
