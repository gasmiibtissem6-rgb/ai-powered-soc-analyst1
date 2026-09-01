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


def test_register_route_requires_admin():
    register_route = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/auth/register"
        and "POST" in getattr(route, "methods", set())
    )

    dependency_names = {
        dependency.call.__name__
        for dependency in register_route.dependant.dependencies
        if getattr(dependency, "call", None) is not None
    }

    assert "require_admin" in dependency_names
