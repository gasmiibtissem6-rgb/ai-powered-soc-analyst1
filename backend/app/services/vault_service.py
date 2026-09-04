from typing import Any, Dict, Optional

import hvac

from app.core.config import settings


class VaultService:
    """
    Service responsible for reading application secrets from HashiCorp Vault.
    """

    def __init__(self) -> None:
        self.addr = settings.VAULT_ADDR
        self.token = settings.VAULT_TOKEN
        self.mount_point = settings.VAULT_MOUNT_POINT
        self.secret_path = settings.VAULT_SECRET_PATH

        self.client: Optional[hvac.Client] = None

        if self.addr and self.token:
            self.client = hvac.Client(
                url=self.addr,
                token=self.token,
            )

    def is_configured(self) -> bool:
        return self.client is not None

    def is_authenticated(self) -> bool:
        if self.client is None:
            return False

        try:
            return bool(self.client.is_authenticated())
        except Exception:
            return False

    def get_secrets(self) -> Dict[str, Any]:
        if self.client is None:
            raise RuntimeError(
                "Vault is not configured. "
                "VAULT_ADDR and VAULT_TOKEN are required."
            )

        if not self.is_authenticated():
            raise RuntimeError(
                "Vault authentication failed."
            )

        response = self.client.secrets.kv.v2.read_secret_version(
            path=self.secret_path,
            mount_point=self.mount_point,
        )

        return response["data"]["data"]

    def get_secret(
        self,
        key: str,
        default: Optional[Any] = None,
    ) -> Any:
        secrets = self.get_secrets()
        return secrets.get(key, default)