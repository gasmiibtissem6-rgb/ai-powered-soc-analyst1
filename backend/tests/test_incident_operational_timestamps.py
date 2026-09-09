from datetime import datetime

from app.utils.datetime_utils import utc_now
from unittest.mock import MagicMock

from app.models.incident import Incident
from app.schemas.incident import IncidentUpdate
from app.services.incident_service import IncidentService


def build_incident(status="open"):
    return Incident(
        id=1,
        title="Test incident",
        description="Operational metrics test",
        severity="high",
        status=status,
        source="test",
        detected_at=utc_now(),
    )


def build_mock_db(incident):
    db = MagicMock()

    (
        db.query.return_value
        .filter.return_value
        .first.return_value
    ) = incident

    return db


def test_resolved_status_sets_resolved_at():
    incident = build_incident()
    db = build_mock_db(incident)

    update = IncidentUpdate(
        status="resolved"
    )

    result = IncidentService.update_incident(
        db,
        incident.id,
        update,
    )

    assert result.status == "resolved"
    assert result.resolved_at is not None
    assert isinstance(
        result.resolved_at,
        datetime,
    )

    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(
        incident
    )


def test_closed_status_sets_resolved_at():
    incident = build_incident()
    db = build_mock_db(incident)

    update = IncidentUpdate(
        status="closed"
    )

    result = IncidentService.update_incident(
        db,
        incident.id,
        update,
    )

    assert result.status == "closed"
    assert result.resolved_at is not None


def test_reopened_incident_clears_resolved_at():
    incident = build_incident(
        status="resolved"
    )
    incident.resolved_at = utc_now()

    db = build_mock_db(incident)

    update = IncidentUpdate(
        status="open"
    )

    result = IncidentService.update_incident(
        db,
        incident.id,
        update,
    )

    assert result.status == "open"
    assert result.resolved_at is None


def test_update_without_status_keeps_resolved_at():
    incident = build_incident(
        status="resolved"
    )

    original_resolved_at = utc_now()
    incident.resolved_at = original_resolved_at

    db = build_mock_db(incident)

    update = IncidentUpdate(
        severity="critical"
    )

    result = IncidentService.update_incident(
        db,
        incident.id,
        update,
    )

    assert (
        result.resolved_at
        == original_resolved_at
    )


def test_unknown_incident_returns_none():
    db = MagicMock()

    (
        db.query.return_value
        .filter.return_value
        .first.return_value
    ) = None

    update = IncidentUpdate(
        status="resolved"
    )

    result = IncidentService.update_incident(
        db,
        999999,
        update,
    )

    assert result is None
    db.commit.assert_not_called()
