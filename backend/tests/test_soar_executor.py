from app.services.soar_executor_service import SOARExecutorService


def test_disable_user_dry_run(monkeypatch):
    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SOAR_EXECUTION_MODE",
        "dry_run",
    )

    result = SOARExecutorService.disable_user(
        "security-user@example.com"
    )

    assert result["success"] is True
    assert result["executed"] is False
    assert result["simulated"] is True
    assert result["mode"] == "dry_run"
    assert result["action_type"] == "disable_user"
    assert result["target"] == "security-user@example.com"


def test_disable_user_rejects_invalid_target():
    result = SOARExecutorService.disable_user(
        "unknown"
    )

    assert result["success"] is False
    assert result["executed"] is False
    assert result["simulated"] is False
    assert result["action_type"] == "disable_user"


def test_execute_routes_disable_user(monkeypatch):
    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SOAR_EXECUTION_MODE",
        "dry_run",
    )

    result = SOARExecutorService.execute(
        action_type="disable_user",
        target="security-user@example.com",
    )

    assert result["success"] is True
    assert result["simulated"] is True
    assert result["action_type"] == "disable_user"


def test_send_notification_dry_run(monkeypatch):
    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SOAR_EXECUTION_MODE",
        "dry_run",
    )

    result = SOARExecutorService.send_notification(
        "soc-team"
    )

    assert result["success"] is True
    assert result["executed"] is False
    assert result["simulated"] is True
    assert result["mode"] == "dry_run"
    assert result["action_type"] == "send_notification"
    assert result["target"] == "soc-team"


def test_send_notification_rejects_invalid_target():
    result = SOARExecutorService.send_notification(
        "unknown"
    )

    assert result["success"] is False
    assert result["executed"] is False
    assert result["simulated"] is False
    assert result["action_type"] == "send_notification"


def test_execute_routes_send_notification(monkeypatch):
    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SOAR_EXECUTION_MODE",
        "dry_run",
    )

    result = SOARExecutorService.execute(
        action_type="send_notification",
        target="soc-team",
    )

    assert result["success"] is True
    assert result["simulated"] is True
    assert result["action_type"] == "send_notification"


def test_shuffle_not_called_in_dry_run(
    monkeypatch,
):
    def shuffle_must_not_run(*args, **kwargs):
        raise AssertionError(
            "Shuffle must not run in dry-run mode"
        )

    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "ShuffleService.trigger_workflow",
        shuffle_must_not_run,
    )

    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SHUFFLE_ENABLED",
        True,
    )

    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SOAR_EXECUTION_MODE",
        "dry_run",
    )

    result = SOARExecutorService.execute(
        action_type="block_ip",
        target="8.8.8.8",
        incident_id=42,
    )

    assert result["success"] is True
    assert result["simulated"] is True
    assert result["mode"] == "dry_run"


def test_shuffle_receives_incident_id_when_enabled(
    monkeypatch,
):
    captured = {}

    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SOAR_EXECUTION_MODE",
        "live",
    )

    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SHUFFLE_ENABLED",
        True,
    )

    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "settings.SOAR_ENABLE_BLOCK_IP",
        True,
    )

    def fake_trigger(
        action_type,
        target,
        incident_id=None,
    ):
        captured["action_type"] = action_type
        captured["target"] = target
        captured["incident_id"] = incident_id

        return {
            "success": True,
            "executed": True,
            "provider": "shuffle",
        }

    monkeypatch.setattr(
        "app.services.soar_executor_service."
        "ShuffleService.trigger_workflow",
        fake_trigger,
    )

    result = SOARExecutorService.execute(
        action_type="block_ip",
        target="8.8.8.8",
        incident_id=42,
    )

    assert result["success"] is True
    assert result["executed"] is True
    assert result["provider"] == "shuffle"

    assert captured == {
        "action_type": "block_ip",
        "target": "8.8.8.8",
        "incident_id": 42,
    }

def test_shuffle_does_not_bypass_block_ip_feature_flag(monkeypatch):
    from app.core.config import settings
    from app.services.soar_executor_service import SOARExecutorService
    from app.services.shuffle_service import ShuffleService

    monkeypatch.setattr(settings, "SOAR_EXECUTION_MODE", "live")
    monkeypatch.setattr(settings, "SHUFFLE_ENABLED", True)
    monkeypatch.setattr(settings, "SOAR_ENABLE_BLOCK_IP", False)

    called = {"value": False}

    def fake_trigger_workflow(*args, **kwargs):
        called["value"] = True
        return {"success": True}

    monkeypatch.setattr(
        ShuffleService,
        "trigger_workflow",
        fake_trigger_workflow,
    )

    result = SOARExecutorService.execute(
        "block_ip",
        "203.0.113.10",
        incident_id=123,
    )

    assert result["success"] is False
    assert result["executed"] is False
    assert called["value"] is False


def test_shuffle_does_not_bypass_notification_validation(monkeypatch):
    from app.core.config import settings
    from app.services.soar_executor_service import SOARExecutorService
    from app.services.shuffle_service import ShuffleService

    monkeypatch.setattr(settings, "SOAR_EXECUTION_MODE", "live")
    monkeypatch.setattr(settings, "SHUFFLE_ENABLED", True)
    monkeypatch.setattr(
        settings,
        "SOAR_ENABLE_SEND_NOTIFICATION",
        True,
    )

    called = {"value": False}

    def fake_trigger_workflow(*args, **kwargs):
        called["value"] = True
        return {"success": True}

    monkeypatch.setattr(
        ShuffleService,
        "trigger_workflow",
        fake_trigger_workflow,
    )

    result = SOARExecutorService.execute(
        "send_notification",
        "unknown",
        incident_id=123,
    )

    assert result["success"] is False
    assert result["executed"] is False
    assert called["value"] is False


def test_shuffle_receives_incident_id_after_safety_checks(monkeypatch):
    from app.core.config import settings
    from app.services.soar_executor_service import SOARExecutorService
    from app.services.shuffle_service import ShuffleService

    monkeypatch.setattr(settings, "SOAR_EXECUTION_MODE", "live")
    monkeypatch.setattr(settings, "SHUFFLE_ENABLED", True)
    monkeypatch.setattr(settings, "SOAR_ENABLE_BLOCK_IP", True)

    captured = {}

    def fake_trigger_workflow(
        action_type,
        target,
        incident_id=None,
    ):
        captured["action_type"] = action_type
        captured["target"] = target
        captured["incident_id"] = incident_id
        return {
            "success": True,
            "executed": True,
            "provider": "shuffle",
        }

    monkeypatch.setattr(
        ShuffleService,
        "trigger_workflow",
        fake_trigger_workflow,
    )

    result = SOARExecutorService.execute(
        "block_ip",
        "203.0.113.10",
        incident_id=456,
    )

    assert result["success"] is True
    assert result["executed"] is True
    assert captured == {
        "action_type": "block_ip",
        "target": "203.0.113.10",
        "incident_id": 456,
    }
