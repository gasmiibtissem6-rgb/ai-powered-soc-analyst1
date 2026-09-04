import pytest

from app.services.vault_service import VaultService


def test_vault_not_configured(monkeypatch):
    monkeypatch.setattr(
        "app.services.vault_service.settings.VAULT_ADDR",
        "",
    )
    monkeypatch.setattr(
        "app.services.vault_service.settings.VAULT_TOKEN",
        "",
    )

    service = VaultService()

    assert service.is_configured() is False
    assert service.is_authenticated() is False


def test_vault_get_secrets_when_not_configured(monkeypatch):
    monkeypatch.setattr(
        "app.services.vault_service.settings.VAULT_ADDR",
        "",
    )
    monkeypatch.setattr(
        "app.services.vault_service.settings.VAULT_TOKEN",
        "",
    )

    service = VaultService()

    with pytest.raises(
        RuntimeError,
        match="Vault is not configured",
    ):
        service.get_secrets()
