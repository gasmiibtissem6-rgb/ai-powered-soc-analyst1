import asyncio

from app.services import vault_token_renewal_service


class FakeVault:
    def __init__(
        self,
        configured=True,
        renew_results=None,
    ):
        self.configured = configured
        self.renew_results = list(
            renew_results or []
        )
        self.renew_calls = 0

    def is_configured(self):
        return self.configured

    def renew_token(self):
        self.renew_calls += 1

        if self.renew_results:
            result = self.renew_results.pop(0)

            if isinstance(result, Exception):
                raise result

            return result

        return True


def test_vault_token_renewal_success(
    monkeypatch,
):
    fake_vault = FakeVault(
        configured=True,
        renew_results=[True],
    )

    monkeypatch.setattr(
        vault_token_renewal_service,
        "VaultService",
        lambda: fake_vault,
    )

    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)
        raise asyncio.CancelledError

    monkeypatch.setattr(
        vault_token_renewal_service.asyncio,
        "sleep",
        fake_sleep,
    )

    try:
        asyncio.run(
            vault_token_renewal_service
            .vault_token_renewal_loop()
        )
    except asyncio.CancelledError:
        pass

    assert fake_vault.renew_calls == 1
    assert sleep_calls == [
        vault_token_renewal_service.RENEW_INTERVAL_SECONDS
    ]


def test_vault_token_renewal_failure_retries(
    monkeypatch,
):
    fake_vault = FakeVault(
        configured=True,
        renew_results=[False],
    )

    monkeypatch.setattr(
        vault_token_renewal_service,
        "VaultService",
        lambda: fake_vault,
    )

    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)
        raise asyncio.CancelledError

    monkeypatch.setattr(
        vault_token_renewal_service.asyncio,
        "sleep",
        fake_sleep,
    )

    try:
        asyncio.run(
            vault_token_renewal_service
            .vault_token_renewal_loop()
        )
    except asyncio.CancelledError:
        pass

    assert fake_vault.renew_calls == 1
    assert sleep_calls == [
        vault_token_renewal_service.RETRY_INTERVAL_SECONDS
    ]


def test_vault_token_renewal_skips_when_not_configured(
    monkeypatch,
):
    fake_vault = FakeVault(
        configured=False,
    )

    monkeypatch.setattr(
        vault_token_renewal_service,
        "VaultService",
        lambda: fake_vault,
    )

    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)
        raise asyncio.CancelledError

    monkeypatch.setattr(
        vault_token_renewal_service.asyncio,
        "sleep",
        fake_sleep,
    )

    try:
        asyncio.run(
            vault_token_renewal_service
            .vault_token_renewal_loop()
        )
    except asyncio.CancelledError:
        pass

    assert fake_vault.renew_calls == 0
    assert sleep_calls == [
        vault_token_renewal_service.RETRY_INTERVAL_SECONDS
    ]
