import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

from starlette.requests import Request
from starlette.responses import JSONResponse

import app.main as main_module


def make_request(
    path="/metrics",
    method="GET",
    authorization=None,
):
    headers = []

    if authorization:
        headers.append(
            (
                b"authorization",
                authorization.encode(),
            )
        )

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }

    return Request(scope)


def test_security_audit_logs_401(
    monkeypatch,
):
    request = make_request(
        path="/metrics",
    )

    db = MagicMock()
    session_factory = MagicMock(
        return_value=db
    )
    log_event = MagicMock()

    monkeypatch.setattr(
        main_module,
        "SessionLocal",
        session_factory,
    )
    monkeypatch.setattr(
        main_module.AuditService,
        "log_event",
        log_event,
    )

    async def call_next(_request):
        return JSONResponse(
            {"detail": "Unauthorized"},
            status_code=401,
        )

    response = asyncio.run(
        main_module.security_audit_middleware(
            request,
            call_next,
        )
    )

    assert response.status_code == 401

    log_event.assert_called_once()

    kwargs = log_event.call_args.kwargs

    assert (
        kwargs["event_type"]
        == "security.authentication_failed"
    )
    assert kwargs["outcome"] == "failure"
    assert kwargs["request_path"] == "/metrics"
    assert kwargs["request_method"] == "GET"
    assert kwargs["actor_subject"] is None
    assert kwargs["details"]["status_code"] == 401

    db.close.assert_called_once()


def test_security_audit_logs_403_with_actor(
    monkeypatch,
):
    request = make_request(
        path="/auth/register",
        method="POST",
        authorization="Bearer test-token",
    )

    principal = SimpleNamespace(
        subject="42",
        source="internal",
        email="analyst@example.com",
    )

    db = MagicMock()
    log_event = MagicMock()

    monkeypatch.setattr(
        main_module,
        "SessionLocal",
        MagicMock(return_value=db),
    )
    monkeypatch.setattr(
        main_module,
        "decode_any_access_token",
        MagicMock(return_value=principal),
    )
    monkeypatch.setattr(
        main_module.AuditService,
        "log_event",
        log_event,
    )

    async def call_next(_request):
        return JSONResponse(
            {"detail": "Forbidden"},
            status_code=403,
        )

    response = asyncio.run(
        main_module.security_audit_middleware(
            request,
            call_next,
        )
    )

    assert response.status_code == 403

    log_event.assert_called_once()

    kwargs = log_event.call_args.kwargs

    assert (
        kwargs["event_type"]
        == "security.access_denied"
    )
    assert kwargs["outcome"] == "denied"
    assert kwargs["actor_subject"] == "42"
    assert kwargs["actor_source"] == "internal"
    assert (
        kwargs["actor_email"]
        == "analyst@example.com"
    )
    assert kwargs["request_path"] == "/auth/register"
    assert kwargs["details"]["status_code"] == 403

    db.close.assert_called_once()


def test_login_401_is_not_duplicated(
    monkeypatch,
):
    request = make_request(
        path="/auth/login",
        method="POST",
    )

    session_factory = MagicMock()
    log_event = MagicMock()

    monkeypatch.setattr(
        main_module,
        "SessionLocal",
        session_factory,
    )
    monkeypatch.setattr(
        main_module.AuditService,
        "log_event",
        log_event,
    )

    async def call_next(_request):
        return JSONResponse(
            {"detail": "Invalid credentials"},
            status_code=401,
        )

    response = asyncio.run(
        main_module.security_audit_middleware(
            request,
            call_next,
        )
    )

    assert response.status_code == 401
    session_factory.assert_not_called()
    log_event.assert_not_called()
