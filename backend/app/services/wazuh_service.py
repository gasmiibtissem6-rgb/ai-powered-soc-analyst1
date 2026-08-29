from typing import Any

from sqlalchemy.orm import Session

from app.schemas.incident import IncidentCreate
from app.services.incident_service import IncidentService


class WazuhService:
    """
    Service responsible for normalizing Wazuh alerts
    before sending them to the SOC workflow.
    """

    def normalize_alert(
        self,
        alert: dict[str, Any],
    ) -> dict[str, Any]:

        rule = alert.get("rule", {}) or {}
        agent = alert.get("agent", {}) or {}
        data = alert.get("data", {}) or {}

        source_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("source_ip")
        )

        destination_ip = (
            data.get("dstip")
            or data.get("dst_ip")
            or data.get("destination_ip")
        )

        username = (
            data.get("srcuser")
            or data.get("dstuser")
            or data.get("user")
            or data.get("username")
        )

        hostname = (
            agent.get("name")
            or data.get("hostname")
        )

        rule_level = rule.get("level", 0)

        try:
            rule_level = int(rule_level)
        except (TypeError, ValueError):
            rule_level = 0

        severity = self._map_severity(
            rule_level
        )

        title = (
            rule.get("description")
            or "Wazuh security alert"
        )

        description = (
            alert.get("full_log")
            or alert.get("message")
            or title
        )

        return {
            "title": title,
            "description": description,
            "severity": severity,
            "source": "Wazuh",
            "hostname": hostname,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "username": username,
            "wazuh_rule_id": rule.get("id"),
            "wazuh_rule_level": rule_level,
            "raw_alert": alert,
        }

    def _map_severity(
        self,
        rule_level: int,
    ) -> str:

        if rule_level >= 12:
            return "critical"

        if rule_level >= 8:
            return "high"

        if rule_level >= 4:
            return "medium"

        return "low"

    def build_incident_data(
        self,
        alert: dict[str, Any],
    ) -> dict[str, Any]:

        normalized = self.normalize_alert(
            alert
        )

        return {
            "title": normalized.get("title"),
            "description": normalized.get("description"),
            "severity": normalized.get(
                "severity",
                "medium",
            ),
            "source": "Wazuh",
            "hostname": normalized.get("hostname"),
            "source_ip": normalized.get("source_ip"),
            "destination_ip": normalized.get("destination_ip"),
            "username": normalized.get("username"),
        }

    def create_incident_from_alert(
        self,
        db: Session,
        alert: dict[str, Any],
    ):
        """
        Create a SOC incident directly from
        a normalized Wazuh alert.
        """

        incident_data = self.build_incident_data(
            alert
        )

        incident_create = IncidentCreate(
            **incident_data
        )

        incident = IncidentService.create_incident(
            db=db,
            incident_data=incident_create,
        )

        return incident