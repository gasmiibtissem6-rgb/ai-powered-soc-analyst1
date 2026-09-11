from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import get_db
from app.core.secrets import secret_manager
from app.models.incident import Incident
from app.models.alert import Alert


# =========================================================
# ISOLATED TEST DATABASE
# =========================================================

TEST_DATABASE_URL = "sqlite://"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={
        "check_same_thread": False,
    },
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def override_get_db():
    db = TestingSessionLocal()

    try:
        yield db

    finally:
        db.close()


# =========================================================
# E2E TEST
# =========================================================

def test_wazuh_soc_workflow_end_to_end(
    monkeypatch,
):
    # Only create tables needed by this E2E scenario.
    Incident.__table__.create(
        bind=engine,
        checkfirst=True,
    )

    Alert.__table__.create(
        bind=engine,
        checkfirst=True,
    )

    app.dependency_overrides[get_db] = (
        override_get_db
    )

    # -----------------------------------------------------
    # Fake ingestion secret
    # -----------------------------------------------------

    original_secret_get = secret_manager.get

    def fake_secret_get(
        key,
        default=None,
    ):
        if key == "SOC_INGESTION_API_KEY":
            return "e2e-test-ingestion-key"

        return original_secret_get(
            key,
            default,
        )

    monkeypatch.setattr(
        secret_manager,
        "get",
        fake_secret_get,
    )

    # -----------------------------------------------------
    # Mock only external / AI SOC workflow
    # -----------------------------------------------------

    workflow_calls = []

    def fake_run_soc_workflow(
        db,
        incident,
        request=None,
    ):
        workflow_calls.append(
            incident.id
        )

        return {
            "status": "completed",
            "thread_id": "e2e-test-thread",
            "incident_id": incident.id,
        }

    monkeypatch.setattr(
        "app.api.wazuh.run_soc_workflow",
        fake_run_soc_workflow,
    )

    client = TestClient(app)

    alert = {
        "timestamp": (
            "2026-09-09T10:00:00Z"
        ),
        "rule": {
            "id": "5710",
            "level": 12,
            "description": (
                "E2E SSH brute force detected"
            ),
            "mitre": {
                "id": [
                    "T1110",
                ],
                "technique": [
                    "Brute Force",
                ],
                "tactic": [
                    "Credential Access",
                ],
            },
        },
        "agent": {
            "id": "001",
            "name": "e2e-endpoint",
            "ip": "10.0.0.10",
        },
        "data": {
            "srcip": "203.0.113.77",
            "srcuser": "e2e-user",
        },
        "full_log": (
            "Multiple failed SSH authentication "
            "attempts detected"
        ),
    }

    headers = {
        "X-SOC-Ingestion-Key": (
            "e2e-test-ingestion-key"
        ),
    }

    try:
        # =================================================
        # 1. FIRST INGESTION
        # =================================================

        response = client.post(
            "/wazuh/alerts",
            json=alert,
            headers=headers,
        )

        assert response.status_code == 201

        data = response.json()

        assert data["status"] == "processed"

        assert (
            data["incident"]["source"]
            == "Wazuh"
        )

        assert (
            data["incident"]["title"]
            == "E2E SSH brute force detected"
        )

        assert (
            data["incident"]["severity"]
            == "critical"
        )

        assert (
            data["incident"]["hostname"]
            == "e2e-endpoint"
        )

        assert (
            data["incident"]["source_ip"]
            == "203.0.113.77"
        )

        assert (
            data["incident"]["username"]
            == "e2e-user"
        )

        assert (
            data["wazuh"]["rule_id"]
            == "5710"
        )

        assert (
            data["wazuh"]["rule_level"]
            == 12
        )

        assert (
            data["wazuh"]["mitre_ids"]
            == ["T1110"]
        )

        assert (
            data["workflow"]["status"]
            == "completed"
        )

        incident_id = data["incident"]["id"]

        assert workflow_calls == [
            incident_id
        ]

        # =================================================
        # 2. DUPLICATE INGESTION
        # =================================================

        duplicate_response = client.post(
            "/wazuh/alerts",
            json=alert,
            headers=headers,
        )

        assert (
            duplicate_response.status_code
            == 201
        )

        duplicate = (
            duplicate_response.json()
        )

        assert (
            duplicate["status"]
            == "duplicate"
        )

        assert (
            duplicate["incident"]["id"]
            == incident_id
        )

        assert (
            duplicate["workflow"]["status"]
            == "not_started"
        )

        assert (
            duplicate["workflow"]["reason"]
            == "duplicate_incident"
        )

        # Workflow must run only once.
        assert workflow_calls == [
            incident_id
        ]

    finally:
        app.dependency_overrides.clear()

        Alert.__table__.drop(
            bind=engine,
            checkfirst=True,
        )

        Incident.__table__.drop(
            bind=engine,
            checkfirst=True,
        )


def test_suricata_soc_workflow_end_to_end(
    monkeypatch,
):
    # Only create tables needed by this E2E scenario.
    Incident.__table__.create(
        bind=engine,
        checkfirst=True,
    )

    Alert.__table__.create(
        bind=engine,
        checkfirst=True,
    )

    app.dependency_overrides[get_db] = (
        override_get_db
    )

    # -----------------------------------------------------
    # Fake ingestion secret
    # -----------------------------------------------------

    original_secret_get = secret_manager.get

    def fake_secret_get(
        key,
        default=None,
    ):
        if key == "SOC_INGESTION_API_KEY":
            return "e2e-test-ingestion-key"

        return original_secret_get(
            key,
            default,
        )

    monkeypatch.setattr(
        secret_manager,
        "get",
        fake_secret_get,
    )

    # -----------------------------------------------------
    # Mock only external / AI SOC workflow
    # -----------------------------------------------------

    workflow_calls = []

    def fake_run_soc_workflow(
        db,
        incident,
        request=None,
        suricata_event=None,
    ):
        workflow_calls.append(
            {
                "incident_id": incident.id,
                "suricata_event": suricata_event,
            }
        )

        return {
            "status": "completed",
            "thread_id": "e2e-suricata-thread",
            "incident_id": incident.id,
        }

    monkeypatch.setattr(
        "app.api.suricata.run_soc_workflow",
        fake_run_soc_workflow,
    )

    client = TestClient(app)

    alert = {
        "timestamp": "2026-09-09T11:00:00Z",
        "event_type": "alert",
        "src_ip": "198.51.100.77",
        "src_port": 44444,
        "dest_ip": "10.0.0.25",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature_id": 2100498,
            "rev": 7,
            "gid": 1,
            "signature": (
                "E2E Suspicious TLS traffic detected"
            ),
            "category": (
                "Potentially Bad Traffic"
            ),
            "severity": 1,
        },
    }

    headers = {
        "X-SOC-Ingestion-Key": (
            "e2e-test-ingestion-key"
        ),
    }

    try:
        # =================================================
        # 1. FIRST INGESTION
        # =================================================

        response = client.post(
            "/suricata/alerts",
            json=alert,
            headers=headers,
        )

        assert response.status_code == 201

        data = response.json()

        assert data["status"] == "processed"

        assert (
            data["incident"]["source"]
            == "Suricata"
        )

        assert (
            data["incident"]["title"]
            == "E2E Suspicious TLS traffic detected"
        )

        assert (
            data["incident"]["severity"]
            == "critical"
        )

        assert (
            data["incident"]["source_ip"]
            == "198.51.100.77"
        )

        assert (
            data["incident"]["destination_ip"]
            == "10.0.0.25"
        )

        assert (
            data["suricata"]["event_type"]
            == "alert"
        )

        assert (
            data["suricata"]["signature_id"]
            == 2100498
        )

        assert (
            data["suricata"]["severity"]
            == 1
        )

        assert (
            data["suricata"]["protocol"]
            == "TCP"
        )

        assert (
            data["workflow"]["status"]
            == "completed"
        )

        incident_id = data["incident"]["id"]

        assert len(workflow_calls) == 1

        assert (
            workflow_calls[0]["incident_id"]
            == incident_id
        )

        assert (
            workflow_calls[0]["suricata_event"]
            == alert
        )

        # =================================================
        # 2. DUPLICATE INGESTION
        # =================================================

        duplicate_response = client.post(
            "/suricata/alerts",
            json=alert,
            headers=headers,
        )

        assert (
            duplicate_response.status_code
            == 201
        )

        duplicate = (
            duplicate_response.json()
        )

        assert (
            duplicate["status"]
            == "duplicate"
        )

        assert (
            duplicate["incident"]["id"]
            == incident_id
        )

        assert (
            duplicate["workflow"]["status"]
            == "not_started"
        )

        assert (
            duplicate["workflow"]["reason"]
            == "duplicate_incident"
        )

        # Workflow must still have run only once.
        assert len(workflow_calls) == 1

    finally:
        app.dependency_overrides.clear()

        Alert.__table__.drop(
            bind=engine,
            checkfirst=True,
        )

        Incident.__table__.drop(
            bind=engine,
            checkfirst=True,
        )

def test_wazuh_rejects_empty_payload(
    monkeypatch,
):
    app.dependency_overrides[get_db] = (
        override_get_db
    )

    original_secret_get = secret_manager.get

    def fake_secret_get(
        key,
        default=None,
    ):
        if key == "SOC_INGESTION_API_KEY":
            return "e2e-test-ingestion-key"

        return original_secret_get(
            key,
            default,
        )

    monkeypatch.setattr(
        secret_manager,
        "get",
        fake_secret_get,
    )

    client = TestClient(app)

    headers = {
        "X-SOC-Ingestion-Key": (
            "e2e-test-ingestion-key"
        ),
    }

    try:
        response = client.post(
            "/wazuh/alerts",
            json={},
            headers=headers,
        )

        assert response.status_code == 400
        assert (
            response.json()["detail"]
            == "Unable to normalize Wazuh alert"
        )

    finally:
        app.dependency_overrides.clear()


def test_wazuh_rejects_empty_opensearch_source(
    monkeypatch,
):
    app.dependency_overrides[get_db] = (
        override_get_db
    )

    original_secret_get = secret_manager.get

    def fake_secret_get(
        key,
        default=None,
    ):
        if key == "SOC_INGESTION_API_KEY":
            return "e2e-test-ingestion-key"

        return original_secret_get(
            key,
            default,
        )

    monkeypatch.setattr(
        secret_manager,
        "get",
        fake_secret_get,
    )

    client = TestClient(app)

    headers = {
        "X-SOC-Ingestion-Key": (
            "e2e-test-ingestion-key"
        ),
    }

    try:
        response = client.post(
            "/wazuh/alerts",
            json={
                "_source": {},
            },
            headers=headers,
        )

        assert response.status_code == 400
        assert (
            response.json()["detail"]
            == "Unable to normalize Wazuh alert"
        )

    finally:
        app.dependency_overrides.clear()