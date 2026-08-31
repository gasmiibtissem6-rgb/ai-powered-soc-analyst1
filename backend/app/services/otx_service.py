import time

import requests

from app.core.config import settings


class OTXService:
    """
    Threat Intelligence enrichment using AlienVault OTX.

    Supported IOC types:
    - IPv4
    - Domain
    - URL
    - File hash
    """

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self):
        self.api_key = settings.OTX_API_KEY

        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

    # =====================================================
    # HTTP REQUEST
    # =====================================================

    def _request(self, endpoint: str) -> dict:
        if not self.api_key:
            raise RuntimeError(
                "OTX_API_KEY is not configured."
            )

        url = f"{self.BASE_URL}/{endpoint}"

        max_attempts = 2
        last_error = None

        for attempt in range(1, max_attempts + 1):

            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=(5, 20),
                )

                response.raise_for_status()

                return response.json()

            except requests.Timeout as exc:
                last_error = exc

                if attempt < max_attempts:
                    time.sleep(1)
                    continue

                raise RuntimeError(
                    "AlienVault OTX request timed out "
                    f"after {max_attempts} attempts."
                ) from exc

            except requests.RequestException:
                raise

        raise RuntimeError(
            f"AlienVault OTX request failed: {last_error}"
        )

    # =====================================================
    # RISK CALCULATION
    # =====================================================

    @staticmethod
    def _calculate_risk(
        ioc_type: str,
        pulse_count: int,
    ) -> str:
        """
        Local SOC heuristic.

        OTX pulse membership alone does not prove
        that an IOC is malicious.
        """

        if pulse_count == 0:
            return "SAFE"

        if ioc_type == "hash":
            if pulse_count >= 5:
                return "MALICIOUS"

            return "SUSPICIOUS"

        return "SUSPICIOUS"

    # =====================================================
    # BUILD RESULT
    # =====================================================

    def _build_result(
        self,
        ioc_type: str,
        value: str,
        response: dict,
    ) -> dict:

        pulse_info = response.get(
            "pulse_info",
            {},
        )

        pulse_count = pulse_info.get(
            "count",
            0,
        )

        return {
            "provider": "AlienVault OTX",
            "ioc_type": ioc_type,
            "value": value,
            "risk": self._calculate_risk(
                ioc_type,
                pulse_count,
            ),
            "pulse_count": pulse_count,
            "pulses": [
                {
                    "name": pulse.get("name"),
                    "id": pulse.get("id"),
                }
                for pulse in pulse_info.get(
                    "pulses",
                    [],
                )[:10]
            ],
        }

    # =====================================================
    # IP
    # =====================================================

    def check_ip(
        self,
        ip_address: str,
    ) -> dict:

        response = self._request(
            f"IPv4/{ip_address}/general"
        )

        return self._build_result(
            "ip",
            ip_address,
            response,
        )

    # =====================================================
    # DOMAIN
    # =====================================================

    def check_domain(
        self,
        domain: str,
    ) -> dict:

        response = self._request(
            f"domain/{domain}/general"
        )

        return self._build_result(
            "domain",
            domain,
            response,
        )

    # =====================================================
    # URL
    # =====================================================

    def check_url(
        self,
        url: str,
    ) -> dict:

        response = self._request(
            f"url/{url}/general"
        )

        return self._build_result(
            "url",
            url,
            response,
        )

    # =====================================================
    # FILE HASH
    # =====================================================

    def check_hash(
        self,
        file_hash: str,
    ) -> dict:

        response = self._request(
            f"file/{file_hash}/general"
        )

        return self._build_result(
            "hash",
            file_hash,
            response,
        )