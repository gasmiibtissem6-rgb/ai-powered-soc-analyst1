from datetime import datetime
from unittest.mock import MagicMock

from app.models.incident import Incident
from app.services.metrics_service import MetricsService


def test_calculate_mttd():
    incident = Incident(
        title="Test MTTD",
        severity="high",
        status="open",
        source="test",
        event_timestamp=datetime(
            2026, 9, 2, 10, 0, 0
        ),
        detected_at=datetime(
            2026, 9, 2, 10, 0, 30
        ),
    )

    metrics = (
        MetricsService
        .calculate_incident_metrics(
            incident
        )
    )

    assert metrics["mttd_seconds"] == 30.0
    assert metrics["mttr_seconds"] is None


def test_calculate_mttr():
    incident = Incident(
        title="Test MTTR",
        severity="high",
        status="resolved",
        source="test",
        detected_at=datetime(
            2026, 9, 2, 10, 0, 0
        ),
        resolved_at=datetime(
            2026, 9, 2, 10, 5, 0
        ),
    )

    metrics = (
        MetricsService
        .calculate_incident_metrics(
            incident
        )
    )

    assert metrics["mttd_seconds"] is None
    assert metrics["mttr_seconds"] == 300.0


def test_calculate_mttd_and_mttr():
    incident = Incident(
        title="Test SOC metrics",
        severity="critical",
        status="resolved",
        source="suricata",
        event_timestamp=datetime(
            2026, 9, 2, 10, 0, 0
        ),
        detected_at=datetime(
            2026, 9, 2, 10, 0, 10
        ),
        resolved_at=datetime(
            2026, 9, 2, 10, 2, 10
        ),
    )

    metrics = (
        MetricsService
        .calculate_incident_metrics(
            incident
        )
    )

    assert metrics["mttd_seconds"] == 10.0
    assert metrics["mttr_seconds"] == 120.0


def test_global_metrics():
    incident_1 = Incident(
        title="Incident 1",
        severity="high",
        status="resolved",
        source="wazuh",
        event_timestamp=datetime(
            2026, 9, 2, 10, 0, 0
        ),
        detected_at=datetime(
            2026, 9, 2, 10, 0, 10
        ),
        resolved_at=datetime(
            2026, 9, 2, 10, 1, 10
        ),
    )

    incident_2 = Incident(
        title="Incident 2",
        severity="high",
        status="resolved",
        source="suricata",
        event_timestamp=datetime(
            2026, 9, 2, 11, 0, 0
        ),
        detected_at=datetime(
            2026, 9, 2, 11, 0, 30
        ),
        resolved_at=datetime(
            2026, 9, 2, 11, 3, 30
        ),
    )

    db = MagicMock()

    db.query.return_value.all.return_value = [
        incident_1,
        incident_2,
    ]

    metrics = MetricsService.get_global_metrics(
        db
    )

    assert metrics["total_incidents"] == 2
    assert metrics["incidents_with_mttd"] == 2
    assert metrics["incidents_with_mttr"] == 2

    assert (
        metrics["average_mttd_seconds"]
        == 20.0
    )

    assert (
        metrics["average_mttr_seconds"]
        == 120.0
    )
