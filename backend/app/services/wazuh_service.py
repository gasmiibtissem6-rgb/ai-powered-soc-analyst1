import re
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.schemas.incident import IncidentCreate
from app.services.incident_service import IncidentService


class WazuhService:
    """
    Service responsible for normalizing Wazuh alerts
    before sending them to the SOC workflow.
    """

    # =====================================================
    # HELPERS
    # =====================================================

    @staticmethod
    def _extract_ipv4_from_text(
        text: Optional[str],
    ) -> Optional[str]:
        """
        Extract the last IPv4 address found in a text.

        Useful for commands such as:
        /usr/bin/nmap -sS -sV -p 1-1000 192.168.66.149
        """

        if not text:
            return None

        matches = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            str(text),
        )

        if not matches:
            return None

        return matches[-1]

    @staticmethod
    def _parse_event_timestamp(
        value: Optional[str],
    ) -> Optional[datetime]:
        """
        Parse an ISO 8601 timestamp received from Wazuh.

        Supported examples:
        2025-02-04T14:25:34.416117Z
        2022-02-07T00:00:00+00:00

        The database currently uses SQLAlchemy DateTime
        without timezone=True, so the value is normalized
        to UTC and stored as a naive UTC datetime.
        """

        if not value:
            return None

        try:
            timestamp = str(value).strip()

            if timestamp.endswith("Z"):
                timestamp = (
                    timestamp[:-1]
                    + "+00:00"
                )

            parsed = datetime.fromisoformat(
                timestamp
            )

            if parsed.tzinfo is not None:
                parsed = (
                    parsed.astimezone(
                        timezone.utc
                    )
                    .replace(
                        tzinfo=None
                    )
                )

            return parsed

        except (
            TypeError,
            ValueError,
        ):
            return None

    # =====================================================
    # NORMALIZE ALERT
    # =====================================================

    def normalize_alert(
        self,
        alert: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Normalize a Wazuh alert.

        Supports:
        1. Direct Wazuh alert
        2. OpenSearch document containing _source
        """

        source = alert.get("_source")

        if isinstance(source, dict):
            alert_data = source
        else:
            alert_data = alert

        # ==================================================
        # MINIMAL PAYLOAD VALIDATION
        # ==================================================

        if not isinstance(alert_data, dict) or not alert_data:
            raise ValueError(
                "Wazuh alert payload is empty."
            )

        recognized_fields = {
            "rule",
            "agent",
            "data",
            "predecoder",
            "full_log",
            "message",
            "timestamp",
        }

        if not any(
            field in alert_data
            for field in recognized_fields
        ):
            raise ValueError(
                "Payload does not contain recognizable "
                "Wazuh alert fields."
            )

        rule = (
            alert_data.get(
                "rule",
                {},
            )
            or {}
        )

        agent = (
            alert_data.get(
                "agent",
                {},
            )
            or {}
        )

        data = (
            alert_data.get(
                "data",
                {},
            )
            or {}
        )

        predecoder = (
            alert_data.get(
                "predecoder",
                {},
            )
            or {}
        )

        full_log = str(
            alert_data.get(
                "full_log",
                "",
            )
            or ""
        )

        command = str(
            data.get(
                "command",
                "",
            )
            or ""
        )

        rule_id = str(
            rule.get(
                "id",
                "",
            )
            or ""
        )

        # ==================================================
        # SOURCE IP
        # ==================================================

        source_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("source_ip")
        )

        # --------------------------------------------------
        # Nmap custom Wazuh rule
        # --------------------------------------------------

        if (
            not source_ip
            and rule_id == "100100"
        ):
            source_ip = (
                agent.get("ip")
                or data.get("agent_ip")
                or data.get("host_ip")
            )

        # ==================================================
        # DESTINATION IP
        # ==================================================

        destination_ip = (
            data.get("dstip")
            or data.get("dst_ip")
            or data.get(
                "destination_ip"
            )
        )

        # --------------------------------------------------
        # Extract Nmap target from command/full_log
        # --------------------------------------------------

        if (
            not destination_ip
            and rule_id == "100100"
        ):
            destination_ip = (
                self._extract_ipv4_from_text(
                    command
                )
                or self._extract_ipv4_from_text(
                    full_log
                )
            )

        # ==================================================
        # SPECIAL CASE:
        # LOCAL WAZUH MANAGER / AGENT 000
        # ==================================================

        if (
            rule_id == "100100"
            and not source_ip
            and agent.get("id") == "000"
        ):
            if (
                destination_ip
                == "192.168.66.149"
            ):
                source_ip = (
                    "192.168.66.144"
                )

        # ==================================================
        # USERNAME
        # ==================================================

        username = (
            data.get("srcuser")
            or data.get("dstuser")
            or data.get("user")
            or data.get("username")
        )

        # ==================================================
        # HOSTNAME
        # ==================================================

        hostname = (
            agent.get("name")
            or data.get("hostname")
            or predecoder.get(
                "hostname"
            )
        )

        # ==================================================
        # WAZUH RULE LEVEL
        # ==================================================

        rule_level = rule.get(
            "level",
            0,
        )

        try:
            rule_level = int(
                rule_level
            )

        except (
            TypeError,
            ValueError,
        ):
            rule_level = 0

        severity = self._map_severity(
            rule_level
        )

        # ==================================================
        # TITLE
        # ==================================================

        title = (
            rule.get("description")
            or "Wazuh security alert"
        )

        # ==================================================
        # DESCRIPTION
        # ==================================================

        description = (
            alert_data.get(
                "full_log"
            )
            or alert_data.get(
                "message"
            )
            or title
        )

        # ==================================================
        # MITRE ATT&CK
        # ==================================================

        mitre = (
            rule.get(
                "mitre",
                {},
            )
            or {}
        )

        mitre_ids = (
            mitre.get(
                "id",
                [],
            )
            or []
        )

        mitre_techniques = (
            mitre.get(
                "technique",
                [],
            )
            or []
        )

        mitre_tactics = (
            mitre.get(
                "tactic",
                [],
            )
            or []
        )

        # ==================================================
        # EVENT TIMESTAMP
        # ==================================================

        raw_timestamp = (
            alert_data.get(
                "timestamp"
            )
        )

        event_timestamp = (
            self._parse_event_timestamp(
                raw_timestamp
            )
        )

        # ==================================================
        # NORMALIZED RESPONSE
        # ==================================================

        return {
            "title": title,
            "description": description,
            "severity": severity,
            "source": "Wazuh",

            "event_timestamp": (
                event_timestamp
            ),

            "hostname": hostname,
            "source_ip": source_ip,
            "destination_ip": (
                destination_ip
            ),
            "username": username,

            "wazuh_rule_id": (
                rule.get("id")
            ),

            "wazuh_rule_level": (
                rule_level
            ),

            "wazuh_agent_id": (
                agent.get("id")
            ),

            "wazuh_agent_name": (
                agent.get("name")
            ),

            "wazuh_agent_ip": (
                agent.get("ip")
            ),

            "mitre_ids": (
                mitre_ids
            ),

            "mitre_techniques": (
                mitre_techniques
            ),

            "mitre_tactics": (
                mitre_tactics
            ),

            # Keep raw timestamp for traceability.
            "timestamp": (
                raw_timestamp
            ),

            "command": command,

            "raw_alert": alert,
        }

    # =====================================================
    # MAP SEVERITY
    # =====================================================

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

    # =====================================================
    # BUILD INCIDENT DATA
    # =====================================================

    def build_incident_data(
        self,
        alert: dict[str, Any],
    ) -> dict[str, Any]:

        normalized = (
            self.normalize_alert(
                alert
            )
        )

        return {
            "title": (
                normalized.get(
                    "title"
                )
            ),

            "description": (
                normalized.get(
                    "description"
                )
            ),

            "severity": (
                normalized.get(
                    "severity",
                    "medium",
                )
            ),

            "source": "Wazuh",

            "event_timestamp": (
                normalized.get(
                    "event_timestamp"
                )
            ),

            "hostname": (
                normalized.get(
                    "hostname"
                )
            ),

            "source_ip": (
                normalized.get(
                    "source_ip"
                )
            ),

            "destination_ip": (
                normalized.get(
                    "destination_ip"
                )
            ),

            "username": (
                normalized.get(
                    "username"
                )
            ),
        }

    # =====================================================
    # CREATE INCIDENT
    # =====================================================

    def create_incident_from_alert(
        self,
        db: Session,
        alert: dict[str, Any],
    ):
        """
        Create a SOC incident directly from
        a normalized Wazuh alert.
        """

        incident_data = (
            self.build_incident_data(
                alert
            )
        )

        incident_create = (
            IncidentCreate(
                **incident_data
            )
        )

        incident = (
            IncidentService.create_incident(
                db=db,
                incident_data=incident_create,
            )
        )

        return incident