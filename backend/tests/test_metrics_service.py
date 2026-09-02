from datetime import datetime
from unittest.mock import MagicMock

import pytest

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
        disposition="true_positive",
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
        disposition="false_positive",
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

    assert metrics["reviewed_incidents"] == 2
    assert metrics["true_positive_count"] == 1
    assert metrics["false_positive_count"] == 1

    assert metrics[
        "false_positive_rate"
    ] == pytest.approx(
        50.0
    )


def test_false_positive_rate():
    incidents = [
        Incident(
            title="True Positive 1",
            severity="high",
            status="resolved",
            source="test",
            disposition="true_positive",
        ),
        Incident(
            title="True Positive 2",
            severity="high",
            status="resolved",
            source="test",
            disposition="true_positive",
        ),
        Incident(
            title="False Positive",
            severity="low",
            status="resolved",
            source="test",
            disposition="false_positive",
        ),
        Incident(
            title="Not Reviewed",
            severity="medium",
            status="open",
            source="test",
            disposition="unknown",
        ),
    ]

    metrics = (
        MetricsService
        .calculate_quality_metrics(
            incidents
        )
    )

    assert metrics["reviewed_incidents"] == 3
    assert metrics["true_positive_count"] == 2
    assert metrics["false_positive_count"] == 1

    assert metrics[
        "false_positive_rate"
    ] == pytest.approx(
        100 / 3
    )


def test_false_positive_rate_without_reviews():
    incidents = [
        Incident(
            title="Unknown Incident",
            severity="medium",
            status="open",
            source="test",
            disposition="unknown",
        ),
    ]

    metrics = (
        MetricsService
        .calculate_quality_metrics(
            incidents
        )
    )

    assert metrics["reviewed_incidents"] == 0
    assert metrics["false_positive_count"] == 0
    assert metrics["true_positive_count"] == 0
    assert metrics["false_positive_rate"] is None