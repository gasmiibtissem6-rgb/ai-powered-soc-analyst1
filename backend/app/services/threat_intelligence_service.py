import re
import requests

from app.core.config import settings


class ThreatIntelligenceService:

    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def check_ip(self, ip_address: str) -> dict:
        """
        Check an IP address using AbuseIPDB.
        """

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
        }

        response = requests.get(
            self.base_url,
            headers=headers,
            params=params,
            timeout=10,
        )

        response.raise_for_status()

        data = response.json()["data"]

        score = data.get("abuseConfidenceScore", 0)

        if score < 25:
            risk = "SAFE"
        elif score < 75:
            risk = "SUSPICIOUS"
        else:
            risk = "MALICIOUS"

        return {
            "ip_address": data.get("ipAddress"),
            "risk": risk,
            "abuse_score": score,
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "total_reports": data.get("totalReports"),
        }

    def extract_ips(self, text: str) -> list[str]:
        """
        Extract IPv4 addresses from text.
        """

        pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

        ips = re.findall(pattern, text)

        return list(set(ips))

    def analyze_text(self, text: str) -> list[dict]:
        """
        Extract IP addresses from text and analyze them with AbuseIPDB.
        """

        ips = self.extract_ips(text)

        results = []

        for ip in ips:
            try:
                result = self.check_ip(ip)
                results.append(result)

            except Exception as e:
                results.append({
                    "ip_address": ip,
                    "error": str(e)
                })

        return results