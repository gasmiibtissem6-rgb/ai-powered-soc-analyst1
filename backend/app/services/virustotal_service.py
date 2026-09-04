import base64
import requests

from app.core.config import settings
from app.core.secrets import secret_manager

class VirusTotalService:
    """
    Threat Intelligence enrichment using VirusTotal API v3.

    Supported IOC types:
    - IP address
    - Domain
    - URL
    - File hash (MD5, SHA1, SHA256)
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = secret_manager.get("VIRUSTOTAL_API_KEY")

        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    # =====================================================
    # INTERNAL HELPERS
    # =====================================================

    def _request(self, endpoint: str) -> dict:
        if not self.api_key:
            raise RuntimeError(
                "VIRUSTOTAL_API_KEY is not configured."
            )

        response = requests.get(
            f"{self.BASE_URL}/{endpoint}",
            headers=self.headers,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()

    @staticmethod
    def _calculate_risk(stats: dict) -> str:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # Several engines agree that the IOC is malicious
        if malicious >= 5:
            return "MALICIOUS"

        # Limited detections should be treated cautiously
        if malicious >= 1 or suspicious >= 1:
            return "SUSPICIOUS"

        return "SAFE"
        
    def _build_result(
        self,
        ioc_type: str,
        value: str,
        response: dict,
    ) -> dict:

        data = response.get("data", {})
        attributes = data.get("attributes", {})

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        return {
            "provider": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "risk": self._calculate_risk(stats),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
        }

    # =====================================================
    # IP
    # =====================================================

    def check_ip(self, ip_address: str) -> dict:
        response = self._request(
            f"ip_addresses/{ip_address}"
        )

        return self._build_result(
            "ip",
            ip_address,
            response,
        )

    # =====================================================
    # DOMAIN
    # =====================================================

    def check_domain(self, domain: str) -> dict:
        response = self._request(
            f"domains/{domain}"
        )

        return self._build_result(
            "domain",
            domain,
            response,
        )

    # =====================================================
    # URL
    # =====================================================

    def check_url(self, url: str) -> dict:
        url_id = (
            base64.urlsafe_b64encode(
                url.encode()
            )
            .decode()
            .strip("=")
        )

        response = self._request(
            f"urls/{url_id}"
        )

        return self._build_result(
            "url",
            url,
            response,
        )

    # =====================================================
    # FILE HASH
    # =====================================================

    def check_hash(self, file_hash: str) -> dict:
        response = self._request(
            f"files/{file_hash}"
        )

        return self._build_result(
            "hash",
            file_hash,
            response,
        )
