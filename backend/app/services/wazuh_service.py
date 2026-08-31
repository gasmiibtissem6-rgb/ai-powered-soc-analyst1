import re
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

    # =====================================================
    # NORMALIZE ALERT
    # =====================================================

    def normalize_alert(
        self,
        alert: dict[str, Any],
    ) -> dict[str, Any]:

        # --------------------------------------------------
        # Support both formats:
        #
        # 1. Direct Wazuh alert
        # 2. OpenSearch document with _source
        # --------------------------------------------------

        source = alert.get("_source")

        if isinstance(source, dict):
            alert_data = source
        else:
            alert_data = alert

        rule = alert_data.get(
            "rule",
            {},
        ) or {}

        agent = alert_data.get(
            "agent",
            {},
        ) or {}

        data = alert_data.get(
            "data",
            {},
        ) or {}

        predecoder = alert_data.get(
            "predecoder",
            {},
        ) or {}

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
        #
        # The scan is executed by the Wazuh manager host.
        # agent.ip may not exist for agent 000, so use
        # known fields when available.
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
            or data.get("destination_ip")
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
            """
            Wazuh agent 000 is the manager itself.

            In our lab, the manager is the machine that
            launches the Nmap scan.

            If its IP is absent from the alert, infer it
            from the known scan topology when destination
            information is available.
            """

            if destination_ip == "192.168.66.149":
                source_ip = "192.168.66.144"

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
            or predecoder.get("hostname")
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
            alert_data.get("full_log")
            or alert_data.get("message")
            or title
        )

        # ==================================================
        # MITRE ATT&CK
        # ==================================================

        mitre = rule.get(
            "mitre",
            {},
        ) or {}

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
        # NORMALIZED RESPONSE
        # ==================================================

        return {
            "title": title,
            "description": description,
            "severity": severity,
            "source": "Wazuh",

            "hostname": hostname,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
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

            "timestamp": (
                alert_data.get(
                    "timestamp"
                )
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

        normalized = self.normalize_alert(
            alert
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

        incident_create = IncidentCreate(
            **incident_data
        )

        incident = (
            IncidentService.create_incident(
                db=db,
                incident_data=incident_create,
            )
        )

        return incident