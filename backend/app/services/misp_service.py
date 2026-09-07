import requests

from app.core.config import settings
from app.core.secrets import secret_manager

class MISPService:
    """
    Threat Intelligence enrichment using MISP.

    MISP is optional. If no MISP instance is configured,
    the SOC workflow continues normally.

    Supported IOC types:
    - IP
    - Domain
    - URL
    - File hash
    """

    def __init__(self):
        self.base_url = (
            settings.MISP_URL.rstrip("/")
            if settings.MISP_URL
            else ""
        )

        self.api_key = secret_manager.get("MISP_API_KEY")
        self.verify_ssl = settings.MISP_VERIFY_SSL

        self.headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # =====================================================
    # CONFIGURATION
    # =====================================================

    def is_configured(self) -> bool:
        return bool(
            self.base_url
            and self.api_key
        )

    def _not_configured(
        self,
        ioc_type: str,
        value: str,
    ) -> dict:
        return {
            "provider": "MISP",
            "ioc_type": ioc_type,
            "value": value,
            "status": "not_configured",
            "risk": "UNKNOWN",
            "match_count": 0,
            "matches": [],
            "reason": (
                "MISP is not configured. "
                "Set MISP_URL and MISP_API_KEY "
                "to enable this provider."
            ),
        }

    # =====================================================
    # SEARCH
    # =====================================================

    def _search(
        self,
        ioc_type: str,
        value: str,
    ) -> dict:

        if not self.is_configured():
            return self._not_configured(
                ioc_type,
                value,
            )

        endpoint = (
            f"{self.base_url}/attributes/restSearch"
        )

        payload = {
            "returnFormat": "json",
            "value": value,
            "limit": 20,
        }

        try:
            response = requests.post(
                endpoint,
                headers=self.headers,
                json=payload,
                timeout=(5, 20),
                verify=self.verify_ssl,
            )

            response.raise_for_status()

            data = response.json()

        except requests.Timeout as exc:
            raise RuntimeError(
                "MISP request timed out."
            ) from exc

        except requests.RequestException as exc:
            raise RuntimeError(
                "MISP request failed."
            ) from exc

        # =================================================
        # NORMALIZE MISP RESPONSE
        # =================================================

        attributes = []

        if isinstance(data, dict):
            response_data = data.get(
                "response",
                data,
            )

            if isinstance(
                response_data,
                dict,
            ):
                attributes = response_data.get(
                    "Attribute",
                    [],
                )

            elif isinstance(
                response_data,
                list,
            ):
                attributes = response_data

        if not isinstance(
            attributes,
            list,
        ):
            attributes = []

        matches = []

        for attribute in attributes[:20]:

            if not isinstance(
                attribute,
                dict,
            ):
                continue

            event = attribute.get(
                "Event",
                {},
            )

            matches.append(
                {
                    "id": attribute.get("id"),
                    "type": attribute.get("type"),
                    "category": attribute.get(
                        "category"
                    ),
                    "value": attribute.get(
                        "value"
                    ),
                    "comment": attribute.get(
                        "comment"
                    ),
                    "event_id": attribute.get(
                        "event_id"
                    ),
                    "event_info": (
                        event.get("info")
                        if isinstance(event, dict)
                        else None
                    ),
                }
            )

        match_count = len(matches)

        risk = (
            "SUSPICIOUS"
            if match_count > 0
            else "SAFE"
        )

        return {
            "provider": "MISP",
            "ioc_type": ioc_type,
            "value": value,
            "status": "success",
            "risk": risk,
            "match_count": match_count,
            "matches": matches,
        }

    # =====================================================
    # IP
    # =====================================================

    def check_ip(
        self,
        ip_address: str,
    ) -> dict:
        return self._search(
            "ip",
            ip_address,
        )

    # =====================================================
    # DOMAIN
    # =====================================================

    def check_domain(
        self,
        domain: str,
    ) -> dict:
        return self._search(
            "domain",
            domain,
        )

    # =====================================================
    # URL
    # =====================================================

    def check_url(
        self,
        url: str,
    ) -> dict:
        return self._search(
            "url",
            url,
        )

    # =====================================================
    # HASH
    # =====================================================

    def check_hash(
        self,
        file_hash: str,
    ) -> dict:
        return self._search(
            "hash",
            file_hash,
        )
