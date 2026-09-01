from app.services.soar_executor_service import SOARExecutorService


def test_disable_user_dry_run():
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


def test_execute_routes_disable_user():
    result = SOARExecutorService.execute(
        action_type="disable_user",
        target="security-user@example.com",
    )

    assert result["success"] is True
    assert result["simulated"] is True
    assert result["action_type"] == "disable_user"
