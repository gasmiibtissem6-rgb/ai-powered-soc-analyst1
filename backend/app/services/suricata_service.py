from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.incident import Incident


class SuricataService:
    """
    Normalize Suricata EVE JSON alerts
    and convert them into SOC incidents.
    """

    @staticmethod
    def normalize_alert(
        alert: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Normalize a Suricata EVE JSON alert.
        """

        event_type = alert.get(
            "event_type"
        )

        if event_type != "alert":
            raise ValueError(
                "Unsupported Suricata event type. "
                "Expected event_type='alert'."
            )

        alert_data = (
            alert.get("alert")
            or {}
        )

        signature = alert_data.get(
            "signature"
        )

        if not signature:
            signature = (
                "Suricata network alert"
            )

        severity_number = alert_data.get(
            "severity"
        )

        severity = (
            SuricataService.map_severity(
                severity_number
            )
        )

        source_ip = alert.get(
            "src_ip"
        )

        destination_ip = alert.get(
            "dest_ip"
        )

        source_port = alert.get(
            "src_port"
        )

        destination_port = alert.get(
            "dest_port"
        )

        protocol = alert.get(
            "proto"
        )

        category = alert_data.get(
            "category"
        )

        signature_id = alert_data.get(
            "signature_id"
        )

        gid = alert_data.get(
            "gid"
        )

        rev = alert_data.get(
            "rev"
        )

        description_parts = []

        if category:
            description_parts.append(
                f"Category: {category}"
            )

        if source_ip:
            source_text = source_ip

            if source_port is not None:
                source_text += (
                    f":{source_port}"
                )

            description_parts.append(
                f"Source: {source_text}"
            )

        if destination_ip:
            destination_text = (
                destination_ip
            )

            if destination_port is not None:
                destination_text += (
                    f":{destination_port}"
                )

            description_parts.append(
                f"Destination: "
                f"{destination_text}"
            )

        if protocol:
            description_parts.append(
                f"Protocol: {protocol}"
            )

        if signature_id is not None:
            description_parts.append(
                f"Signature ID: "
                f"{signature_id}"
            )

        description = "; ".join(
            description_parts
        )

        if not description:
            description = (
                "Suricata network security "
                "alert detected."
            )

        return {
            "title": signature,
            "description": description,
            "severity": severity,
            "status": "open",
            "source": "Suricata",
            "hostname": None,
            "source_ip": source_ip,
            "destination_ip": (
                destination_ip
            ),
            "username": None,

            "suricata": {
                "event_type": event_type,
                "category": category,
                "signature": signature,
                "signature_id": signature_id,
                "severity": severity_number,
                "gid": gid,
                "rev": rev,
                "source_port": source_port,
                "destination_port": (
                    destination_port
                ),
                "protocol": protocol,
            },
        }

    @staticmethod
    def map_severity(
        severity_number: Optional[int],
    ) -> str:
        """
        Convert Suricata numeric severity
        into the platform severity levels.

        Suricata commonly uses:
        1 = highest severity
        2 = medium/high
        3 = lower severity
        """

        if severity_number == 1:
            return "critical"

        if severity_number == 2:
            return "high"

        if severity_number == 3:
            return "medium"

        return "medium"

    @staticmethod
    def create_incident_from_alert(
        db: Session,
        alert: Dict[str, Any],
    ) -> Incident:
        """
        Normalize a Suricata alert and
        persist it as an Incident.
        """

        normalized = (
            SuricataService.normalize_alert(
                alert
            )
        )

        incident = Incident(
            title=normalized[
                "title"
            ],
            description=normalized[
                "description"
            ],
            severity=normalized[
                "severity"
            ],
            status=normalized[
                "status"
            ],
            source=normalized[
                "source"
            ],
            hostname=normalized[
                "hostname"
            ],
            source_ip=normalized[
                "source_ip"
            ],
            destination_ip=normalized[
                "destination_ip"
            ],
            username=normalized[
                "username"
            ],
            workflow_status="pending",
            workflow_error=None,
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return incident
