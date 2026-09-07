import ipaddress
import json

import redis

from app.core.config import settings
from app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
)
from app.services.virustotal_service import VirusTotalService
from app.services.otx_service import OTXService
from app.services.misp_service import MISPService


class ThreatIntelligenceEnrichmentService:
    """
    Centralized Threat Intelligence enrichment service.

    Providers:
    - AbuseIPDB
    - VirusTotal
    - AlienVault OTX
    - MISP

    Supported IOC types:
    - IP
    - Domain
    - URL
    - Hash
    """

    def __init__(self):
        self.abuseipdb = ThreatIntelligenceService()
        self.virustotal = VirusTotalService()
        self.otx = OTXService()
        self.misp = MISPService()

        self.redis = redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
        )
        self.cache_ttl_seconds = 900

    # =====================================================
    # REDIS CACHE
    # =====================================================

    def _get_cached(self, key):
        try:
            cached = self.redis.get(key)

            if cached is None:
                return None

            return json.loads(cached)

        except Exception:
            # Redis must never block TI enrichment.
            return None

    def _set_cached(self, key, value):
        try:
            self.redis.set(
                key,
                json.dumps(value),
                ex=self.cache_ttl_seconds,
            )
        except Exception:
            # Redis must never block TI enrichment.
            pass

    # =====================================================
    # SAFE PROVIDER CALL
    # =====================================================

    @staticmethod
    def _safe_call(
        provider_name,
        callback,
    ):
        try:
            return callback()

        except Exception:
            return {
                "status": "error",
                "provider": provider_name,
                "error": "Threat intelligence provider request failed",
            }

    # =====================================================
    # IP
    # =====================================================

    def enrich_ip(
        self,
        ip_address,
    ):
        cache_key = f"soc:ti:ip:{ip_address}"

        cached = self._get_cached(cache_key)

        if cached is not None:
            return cached

        result = {
            "ioc_type": "ip",
            "value": ip_address,
            "scope": None,
            "providers": {},
        }

        # -------------------------------------------------
        # Validate IP
        # -------------------------------------------------

        try:
            parsed_ip = ipaddress.ip_address(
                ip_address
            )

        except ValueError:
            result["scope"] = "invalid"

            reason = "Invalid IP address"

            result["providers"] = {
                "abuseipdb": {
                    "status": "skipped",
                    "reason": reason,
                },
                "virustotal": {
                    "status": "skipped",
                    "reason": reason,
                },
                "otx": {
                    "status": "skipped",
                    "reason": reason,
                },
                "misp": {
                    "status": "skipped",
                    "reason": reason,
                },
            }

            return result

        # -------------------------------------------------
        # Private / local / reserved IP
        # -------------------------------------------------

        if not parsed_ip.is_global:
            result["scope"] = "private"

            reason = (
                "Non-public IP address. "
                "External threat intelligence lookup skipped."
            )

            result["providers"] = {
                "abuseipdb": {
                    "status": "skipped",
                    "reason": reason,
                },
                "virustotal": {
                    "status": "skipped",
                    "reason": reason,
                },
                "otx": {
                    "status": "skipped",
                    "reason": reason,
                },
                "misp": {
                    "status": "skipped",
                    "reason": reason,
                },
            }

            return result

        # -------------------------------------------------
        # Public IP
        # -------------------------------------------------

        result["scope"] = "public"

        result["providers"]["abuseipdb"] = (
            self._safe_call(
                "AbuseIPDB",
                lambda: self.abuseipdb.check_ip(
                    ip_address
                ),
            )
        )

        result["providers"]["virustotal"] = (
            self._safe_call(
                "VirusTotal",
                lambda: self.virustotal.check_ip(
                    ip_address
                ),
            )
        )

        result["providers"]["otx"] = (
            self._safe_call(
                "AlienVault OTX",
                lambda: self.otx.check_ip(
                    ip_address
                ),
            )
        )

        result["providers"]["misp"] = (
            self._safe_call(
                "MISP",
                lambda: self.misp.check_ip(
                    ip_address
                ),
            )
        )

        self._set_cached(
            cache_key,
            result,
        )

        return result

    # =====================================================
    # DOMAIN
    # =====================================================

    def enrich_domain(
        self,
        domain,
    ):
        return {
            "ioc_type": "domain",
            "value": domain,
            "providers": {
                "virustotal": self._safe_call(
                    "VirusTotal",
                    lambda: self.virustotal.check_domain(
                        domain
                    ),
                ),

                "otx": self._safe_call(
                    "AlienVault OTX",
                    lambda: self.otx.check_domain(
                        domain
                    ),
                ),

                "misp": self._safe_call(
                    "MISP",
                    lambda: self.misp.check_domain(
                        domain
                    ),
                ),
            },
        }

    # =====================================================
    # URL
    # =====================================================

    def enrich_url(
        self,
        url,
    ):
        return {
            "ioc_type": "url",
            "value": url,
            "providers": {
                "virustotal": self._safe_call(
                    "VirusTotal",
                    lambda: self.virustotal.check_url(
                        url
                    ),
                ),

                "otx": self._safe_call(
                    "AlienVault OTX",
                    lambda: self.otx.check_url(
                        url
                    ),
                ),

                "misp": self._safe_call(
                    "MISP",
                    lambda: self.misp.check_url(
                        url
                    ),
                ),
            },
        }

    # =====================================================
    # HASH
    # =====================================================

    def enrich_hash(
        self,
        file_hash,
        hash_type=None,
    ):
        return {
            "ioc_type": "hash",
            "hash_type": hash_type,
            "value": file_hash,
            "providers": {
                "virustotal": self._safe_call(
                    "VirusTotal",
                    lambda: self.virustotal.check_hash(
                        file_hash
                    ),
                ),

                "otx": self._safe_call(
                    "AlienVault OTX",
                    lambda: self.otx.check_hash(
                        file_hash
                    ),
                ),

                "misp": self._safe_call(
                    "MISP",
                    lambda: self.misp.check_hash(
                        file_hash
                    ),
                ),
            },
        }
