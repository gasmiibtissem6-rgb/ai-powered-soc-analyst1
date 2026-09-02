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

def test_metrics_route_requires_analyst():
    metrics_route = next(
        route
        for route in app.routes
        if getattr(
            route,
            "path",
            None,
        ) == "/metrics"
        and "GET" in getattr(
            route,
            "methods",
            set(),
        )
    )

    dependency_names = {
        dependency.call.__name__
        for dependency
        in metrics_route.dependant.dependencies
        if getattr(
            dependency,
            "call",
            None,
        ) is not None
    }

    assert (
        "require_analyst"
        in dependency_names
    )
def test_analyst_ask_route_is_registered():
    paths = get_registered_paths()

    assert "/analyst/ask" in paths


def test_analyst_ask_route_requires_analyst():
    analyst_ask_route = next(
        route
        for route in app.routes
        if getattr(
            route,
            "path",
            None,
        ) == "/analyst/ask"
        and "POST" in getattr(
            route,
            "methods",
            set(),
        )
    )

    dependency_names = {
        dependency.call.__name__
        for dependency
        in analyst_ask_route.dependant.dependencies
        if getattr(
            dependency,
            "call",
            None,
        ) is not None
    }

    assert (
        "require_analyst"
        in dependency_names
    )