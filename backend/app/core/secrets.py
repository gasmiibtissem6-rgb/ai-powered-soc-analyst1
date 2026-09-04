from typing import Any

from app.core.config import settings
from app.services.vault_service import VaultService


class SecretManager:
    """
    Centralized application secret manager.

    Priority:
    1. HashiCorp Vault
    2. Environment / .env fallback
    """

    def __init__(self) -> None:
        self.vault = VaultService()

    def get(self, key: str, default: Any = None) -> Any:
        if self.vault.is_configured() and self.vault.is_authenticated():
            try:
                value = self.vault.get_secret(key)

                if value not in (None, ""):
                    return value
            except Exception:
                pass

        return getattr(settings, key, default)


secret_manager = SecretManager()