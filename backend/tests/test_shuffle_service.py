from app.services.shuffle_service import ShuffleService


class FakeResponse:
    text = '{"execution_id": "exec-123"}'

    def raise_for_status(self):
        return None

    def json(self):
        return {
            "execution_id": "exec-123",
        }


def test_shuffle_rejects_missing_webhook(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.shuffle_service.secret_manager.get",
        lambda key, default="": "",
    )

    result = ShuffleService.trigger_workflow(
        action_type="block_ip",
        target="8.8.8.8",
        incident_id=10,
    )

    assert result["success"] is False
    assert result["executed"] is False
    assert result["provider"] == "shuffle"


def test_shuffle_triggers_workflow(
    monkeypatch,
):
    def fake_secret_get(key, default=""):
        if key == "SHUFFLE_WEBHOOK_URL":
            return "https://shuffle.test/webhook"

        if key == "SHUFFLE_WEBHOOK_SECRET":
            return "test-secret"

        return default

    captured = {}

    def fake_post(
        url,
        json,
        headers,
        timeout,
        verify,
    ):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        captured["verify"] = verify

        return FakeResponse()

    monkeypatch.setattr(
        "app.services.shuffle_service.secret_manager.get",
        fake_secret_get,
    )

    monkeypatch.setattr(
        "app.services.shuffle_service.requests.post",
        fake_post,
    )

    result = ShuffleService.trigger_workflow(
        action_type="block_ip",
        target="8.8.8.8",
        incident_id=42,
    )

    assert result["success"] is True
    assert result["executed"] is True
    assert result["provider"] == "shuffle"

    assert captured["url"] == (
        "https://shuffle.test/webhook"
    )

    assert captured["json"] == {
        "source": "ai-powered-soc-analyst",
        "action_type": "block_ip",
        "target": "8.8.8.8",
        "incident_id": 42,
    }

    assert captured["headers"]["X-SOC-Webhook-Key"] == (
        "test-secret"
    )


def test_shuffle_accepts_non_json_response(
    monkeypatch,
):
    class TextResponse:
        text = "workflow accepted"

        def raise_for_status(self):
            return None

        def json(self):
            raise ValueError

    monkeypatch.setattr(
        "app.services.shuffle_service.secret_manager.get",
        lambda key, default="": (
            "https://shuffle.test/webhook"
            if key == "SHUFFLE_WEBHOOK_URL"
            else ""
        ),
    )

    monkeypatch.setattr(
        "app.services.shuffle_service.requests.post",
        lambda *args, **kwargs: TextResponse(),
    )

    result = ShuffleService.trigger_workflow(
        action_type="send_notification",
        target="soc-team",
    )

    assert result["success"] is True
    assert result["response"] == {
        "raw_response": "workflow accepted"
    }
