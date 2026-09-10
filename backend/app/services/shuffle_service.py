from typing import Any, Dict

import requests

from app.core.config import settings
from app.core.secrets import secret_manager


class ShuffleService:
    """
    Adapter responsible for triggering Shuffle workflows.

    Secrets are resolved through SecretManager so production
    deployments can use Vault without storing credentials in code.
    """

    @staticmethod
    def trigger_workflow(
        action_type: str,
        target: str,
        incident_id: int | None = None,
    ) -> Dict[str, Any]:
        webhook_url = secret_manager.get(
            "SHUFFLE_WEBHOOK_URL",
            settings.SHUFFLE_WEBHOOK_URL,
        )

        webhook_secret = secret_manager.get(
            "SHUFFLE_WEBHOOK_SECRET",
            settings.SHUFFLE_WEBHOOK_SECRET,
        )

        if not webhook_url:
            return {
                "success": False,
                "executed": False,
                "provider": "shuffle",
                "message": "Shuffle webhook is not configured.",
                "action_type": action_type,
                "target": target,
            }

        payload = {
            "source": "ai-powered-soc-analyst",
            "action_type": action_type,
            "target": target,
        }

        if incident_id is not None:
            payload["incident_id"] = incident_id

        headers = {
            "Content-Type": "application/json",
        }

        if webhook_secret:
            headers["X-SOC-Webhook-Key"] = webhook_secret

        try:
            response = requests.post(
                webhook_url,
                json=payload,
                headers=headers,
                timeout=settings.SHUFFLE_TIMEOUT_SECONDS,
                verify=settings.SHUFFLE_VERIFY_SSL,
            )

            response.raise_for_status()

        except requests.RequestException:
            return {
                "success": False,
                "executed": False,
                "provider": "shuffle",
                "message": "Shuffle workflow trigger failed.",
                "action_type": action_type,
                "target": target,
            }

        try:
            response_data = response.json()
        except ValueError:
            response_data = {
                "status": "accepted",
            }

        return {
            "success": True,
            "executed": True,
            "provider": "shuffle",
            "message": "Shuffle workflow triggered successfully.",
            "action_type": action_type,
            "target": target,
            "response": response_data,
        }
