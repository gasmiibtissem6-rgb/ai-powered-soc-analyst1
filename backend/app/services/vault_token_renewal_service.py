import asyncio
import logging

from app.services.vault_service import VaultService


logger = logging.getLogger(__name__)

RENEW_INTERVAL_SECONDS = 12 * 60 * 60
RETRY_INTERVAL_SECONDS = 5 * 60


async def vault_token_renewal_loop() -> None:
    """
    Keep the backend Vault token renewable.

    Renewal is attempted immediately at startup.
    Successful renewals are repeated every 12 hours.
    Failed renewals are retried after 5 minutes.

    Token values are never written to logs.
    """
    vault = VaultService()

    while True:
        try:
            if not vault.is_configured():
                logger.warning(
                    "Vault token renewal skipped: "
                    "Vault is not configured"
                )

                await asyncio.sleep(
                    RETRY_INTERVAL_SECONDS
                )
                continue

            renewed = vault.renew_token()

            if renewed:
                logger.info(
                    "Vault backend token renewed successfully"
                )

                await asyncio.sleep(
                    RENEW_INTERVAL_SECONDS
                )

            else:
                logger.error(
                    "Vault backend token renewal failed"
                )

                await asyncio.sleep(
                    RETRY_INTERVAL_SECONDS
                )

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.error(
                "Unexpected Vault token renewal error"
            )

            await asyncio.sleep(
                RETRY_INTERVAL_SECONDS
            )
