from app.main import app


def get_registered_paths():
    return {route.path for route in app.routes}


def test_core_api_routes_are_registered():
    paths = get_registered_paths()

    expected_paths = {
        "/openapi.json",
        "/docs",
        "/agents/analyze/{incident_id}",
        "/agents/resume/{thread_id}",
        "/reports",
        "/reports/incident/{incident_id}",
        "/reports/{report_id}",
        "/soar/{action_id}/logs",
    }

    missing = expected_paths - paths

    assert not missing, f"Missing API routes: {sorted(missing)}"
