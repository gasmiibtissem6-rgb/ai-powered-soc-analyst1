from fastapi.testclient import TestClient

from app.main import app
from app.core.auth_principal import AuthPrincipal
from app.core.security import get_current_principal


client = TestClient(app)


def analyst_principal() -> AuthPrincipal:
    return AuthPrincipal(
        subject="rbac-analyst",
        roles=["analyst"],
        source="keycloak",
        email="analyst@example.com",
        full_name="RBAC Analyst",
    )


def admin_principal() -> AuthPrincipal:
    return AuthPrincipal(
        subject="rbac-admin",
        roles=["admin"],
        source="keycloak",
        email="admin@example.com",
        full_name="RBAC Administrator",
    )


def override_principal(
    principal: AuthPrincipal,
):
    def dependency():
        return principal

    return dependency


def test_analyst_cannot_access_admin_users():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        analyst_principal()
    )

    try:
        response = client.get(
            "/admin/users"
        )

        assert (
            response.status_code
            == 403
        )

        assert (
            response.json()["detail"]
            == "Insufficient permissions"
        )

    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_delete_alert():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        analyst_principal()
    )

    try:
        response = client.delete(
            "/alerts/999999"
        )

        assert (
            response.status_code
            == 403
        )

        assert (
            response.json()["detail"]
            == "Insufficient permissions"
        )

    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_delete_incident():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        analyst_principal()
    )

    try:
        response = client.delete(
            "/incidents/999999"
        )

        assert (
            response.status_code
            == 403
        )

        assert (
            response.json()["detail"]
            == "Insufficient permissions"
        )

    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_delete_ai_analysis():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        analyst_principal()
    )

    try:
        response = client.delete(
            "/ai-analysis/999999"
        )

        assert (
            response.status_code
            == 403
        )

        assert (
            response.json()["detail"]
            == "Insufficient permissions"
        )

    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_resume_hitl_workflow():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        analyst_principal()
    )

    try:
        response = client.post(
            "/agents/resume/fake-thread",
            json={
                "approved": True,
                "comment": (
                    "RBAC analyst must "
                    "not be allowed"
                ),
            },
        )

        assert (
            response.status_code
            == 403
        )

        assert (
            response.json()["detail"]
            == "Insufficient permissions"
        )

    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_approve_soar_action():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        analyst_principal()
    )

    try:
        response = client.post(
            "/soar/999999/approve"
        )

        assert (
            response.status_code
            == 403
        )

        assert (
            response.json()["detail"]
            == "Insufficient permissions"
        )

    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_reject_soar_action():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        analyst_principal()
    )

    try:
        response = client.post(
            "/soar/999999/reject"
        )

        assert (
            response.status_code
            == 403
        )

        assert (
            response.json()["detail"]
            == "Insufficient permissions"
        )

    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_execute_soar_action():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        analyst_principal()
    )

    try:
        response = client.post(
            "/soar/999999/execute"
        )

        assert (
            response.status_code
            == 403
        )

        assert (
            response.json()["detail"]
            == "Insufficient permissions"
        )

    finally:
        app.dependency_overrides.clear()


def test_admin_is_not_blocked_by_rbac_on_admin_users():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        admin_principal()
    )

    try:
        response = client.get(
            "/admin/users"
        )

        # The request may fail later because this
        # test is not mocking Keycloak Admin API.
        # What matters here is that RBAC itself
        # did not reject the administrator.
        assert (
            response.status_code
            != 403
        )

    finally:
        app.dependency_overrides.clear()


def test_admin_is_not_blocked_by_rbac_on_soar_execute():
    app.dependency_overrides[
        get_current_principal
    ] = override_principal(
        admin_principal()
    )

    try:
        response = client.post(
            "/soar/999999/execute"
        )

        # A nonexistent action may return 404.
        # That is correct: authorization succeeded
        # and processing reached business logic.
        assert (
            response.status_code
            != 403
        )

    finally:
        app.dependency_overrides.clear()