from types import SimpleNamespace

from app.services.soar_service import SOARService
from app.services.soar_executor_service import SOARExecutorService


class FakeDB:
    def commit(self):
        pass

    def refresh(self, obj):
        pass

    def rollback(self):
        pass


def test_isolate_endpoint_invalid_target_stops_execution(
    monkeypatch,
):
    action = SimpleNamespace(
        id=1,
        incident_id=220,
        action_type="isolate_endpoint",
        target="unknown",
        requires_approval=False,
        approved=None,
        status="pending",
        result=None,
    )

    monkeypatch.setattr(
        SOARService,
        "get_action",
        lambda db, action_id: action,
    )

    monkeypatch.setattr(
        SOARService,
        "log_action_event",
        lambda **kwargs: None,
    )

    def executor_must_not_run(*args, **kwargs):
        raise AssertionError(
            "SOAR executor must not run for an unsafe endpoint"
        )

    monkeypatch.setattr(
        SOARExecutorService,
        "execute",
        executor_must_not_run,
    )

    result = SOARService.execute_action(
        db=FakeDB(),
        action_id=1,
    )

    assert result is action
    assert result.status == "blocked_by_safety"
    assert result.result["success"] is False
    assert result.result["target"] == "unknown"
