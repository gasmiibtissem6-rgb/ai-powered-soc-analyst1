from ipaddress import ip_address
from typing import Any, Dict

import requests

from app.core.config import settings
from app.core.secrets import secret_manager


class SOARExecutorService:
    """
    Technical executor for SOAR actions.

    Responsibilities:
    - execute actions in dry-run mode
    - enforce execution feature flags
    - validate targets
    - prepare future real firewall/endpoint integrations

    Real destructive actions remain disabled unless they are
    explicitly enabled in the application configuration.
    """

    # =====================================================
    # MAIN EXECUTOR
    # =====================================================

    @staticmethod
    def execute(
        action_type: str,
        target: str,
    ) -> Dict[str, Any]:
        """
        Execute one SOAR action.

        Supported actions:
        - create_ticket
        - block_ip
        - isolate_endpoint
        - disable_user
        - send_notification
        """

        normalized_action = (
            action_type.strip().lower()
            if action_type
            else ""
        )

        normalized_target = (
            target.strip()
            if target
            else ""
        )

        if not normalized_action:
            return {
                "success": False,
                "executed": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "message": "Missing SOAR action type.",
                "action_type": normalized_action,
                "target": normalized_target,
            }

        if not normalized_target:
            return {
                "success": False,
                "executed": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "message": "Missing SOAR action target.",
                "action_type": normalized_action,
                "target": normalized_target,
            }

        if normalized_action == "create_ticket":
            return SOARExecutorService.create_ticket(
                normalized_target
            )

        if normalized_action == "block_ip":
            return SOARExecutorService.block_ip(
                normalized_target
            )

        if normalized_action == "isolate_endpoint":
            return SOARExecutorService.isolate_endpoint(
                normalized_target
            )

        if normalized_action == "disable_user":
            return SOARExecutorService.disable_user(
                normalized_target
            )

        if normalized_action == "send_notification":
            return SOARExecutorService.send_notification(
                normalized_target
            )

        return {
            "success": False,
            "executed": False,
            "mode": settings.SOAR_EXECUTION_MODE,
            "message": (
                f"Unsupported SOAR action: "
                f"{normalized_action}"
            ),
            "action_type": normalized_action,
            "target": normalized_target,
        }

    # =====================================================
    # DRY-RUN
    # =====================================================

    @staticmethod
    def is_dry_run() -> bool:
        """
        Return True when SOAR runs in simulation mode.
        """

        return (
            settings.SOAR_EXECUTION_MODE
            .strip()
            .lower()
            == "dry_run"
        )

    # =====================================================
    # CREATE TICKET
    # =====================================================

    @staticmethod
    def create_ticket(
        target: str,
    ) -> Dict[str, Any]:
        """
        Prototype ticket creation.
        """

        if SOARExecutorService.is_dry_run():
            return {
                "success": True,
                "executed": False,
                "simulated": True,
                "mode": "dry_run",
                "action_type": "create_ticket",
                "target": target,
                "message": (
                    "DRY RUN: security ticket creation "
                    "simulated successfully."
                ),
            }

        return {
            "success": True,
            "executed": True,
            "simulated": False,
            "mode": settings.SOAR_EXECUTION_MODE,
            "action_type": "create_ticket",
            "target": target,
            "message": (
                "Security ticket action executed "
                "successfully."
            ),
        }

    # =====================================================
    # BLOCK IP
    # =====================================================

    @staticmethod
    def block_ip(
        target: str,
    ) -> Dict[str, Any]:
        """
        Prepare execution of an IP blocking action.
        """

        if not SOARExecutorService.is_safe_ip(target):
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "block_ip",
                "target": target,
                "message": (
                    "SOAR safety policy rejected "
                    "the IP target."
                ),
            }

        if SOARExecutorService.is_dry_run():
            return {
                "success": True,
                "executed": False,
                "simulated": True,
                "mode": "dry_run",
                "action_type": "block_ip",
                "target": target,
                "message": (
                    f"DRY RUN: firewall block for "
                    f"{target} simulated successfully."
                ),
            }

        if not settings.SOAR_ENABLE_BLOCK_IP:
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "block_ip",
                "target": target,
                "message": (
                    "Real IP blocking is disabled by "
                    "SOAR_ENABLE_BLOCK_IP."
                ),
            }

        return {
            "success": False,
            "executed": False,
            "simulated": False,
            "mode": settings.SOAR_EXECUTION_MODE,
            "action_type": "block_ip",
            "target": target,
            "message": (
                "Real firewall execution is enabled in "
                "configuration but no production firewall "
                "adapter has been configured yet."
            ),
        }

    # =====================================================
    # ISOLATE ENDPOINT
    # =====================================================

    @staticmethod
    def isolate_endpoint(
        target: str,
    ) -> Dict[str, Any]:
        """
        Prepare endpoint isolation.
        """

        if not SOARExecutorService.is_safe_endpoint(target):
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "isolate_endpoint",
                "target": target,
                "message": (
                    "SOAR safety policy rejected "
                    "the endpoint target."
                ),
            }

        if SOARExecutorService.is_dry_run():
            return {
                "success": True,
                "executed": False,
                "simulated": True,
                "mode": "dry_run",
                "action_type": "isolate_endpoint",
                "target": target,
                "message": (
                    f"DRY RUN: endpoint isolation for "
                    f"{target} simulated successfully."
                ),
            }

        if not settings.SOAR_ENABLE_ISOLATE_ENDPOINT:
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "isolate_endpoint",
                "target": target,
                "message": (
                    "Real endpoint isolation is disabled "
                    "by SOAR_ENABLE_ISOLATE_ENDPOINT."
                ),
            }

        return {
            "success": False,
            "executed": False,
            "simulated": False,
            "mode": settings.SOAR_EXECUTION_MODE,
            "action_type": "isolate_endpoint",
            "target": target,
            "message": (
                "Endpoint isolation is enabled in "
                "configuration but no production endpoint "
                "isolation adapter has been configured yet."
            ),
        }

    # =====================================================
    # DISABLE USER
    # =====================================================

    @staticmethod
    def disable_user(
        target: str,
    ) -> Dict[str, Any]:
        """
        Prepare disabling a user account.
        """

        if not SOARExecutorService.is_safe_user(target):
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "disable_user",
                "target": target,
                "message": (
                    "SOAR safety policy rejected "
                    "the user target."
                ),
            }

        if SOARExecutorService.is_dry_run():
            return {
                "success": True,
                "executed": False,
                "simulated": True,
                "mode": "dry_run",
                "action_type": "disable_user",
                "target": target,
                "message": (
                    f"DRY RUN: disabling user account "
                    f"{target} simulated successfully."
                ),
            }

        if not settings.SOAR_ENABLE_DISABLE_USER:
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "disable_user",
                "target": target,
                "message": (
                    "Real user disabling is disabled by "
                    "SOAR_ENABLE_DISABLE_USER."
                ),
            }

        return {
            "success": False,
            "executed": False,
            "simulated": False,
            "mode": settings.SOAR_EXECUTION_MODE,
            "action_type": "disable_user",
            "target": target,
            "message": (
                "User disabling is enabled in configuration "
                "but no production identity provider or "
                "directory adapter has been configured yet."
            ),
        }

    # =====================================================
    # USER VALIDATION
    # =====================================================

    @staticmethod
    def is_safe_user(
        target: str,
    ) -> bool:
        """
        Reject unusable user account identifiers.
        """

        if not target:
            return False

        normalized = target.strip().lower()

        unsafe_values = {
            "",
            "unknown",
            "unknown-user",
            "unknown_user",
            "none",
            "null",
            "n/a",
            "na",
            "undefined",
        }

        return normalized not in unsafe_values

    # =====================================================
    # SEND NOTIFICATION
    # =====================================================

    @staticmethod
    def send_notification(
        target: str,
    ) -> Dict[str, Any]:
        """
        Send a SOC notification to Slack or Microsoft Teams.

        Real external delivery is protected by:
        1. notification target validation
        2. dry-run mode
        3. SOAR_ENABLE_SEND_NOTIFICATION feature flag
        4. configured Slack/Teams webhook
        """

        if not SOARExecutorService.is_safe_notification_target(target):
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "send_notification",
                "target": target,
                "message": (
                    "SOAR safety policy rejected "
                    "the notification target."
                ),
            }

        # =================================================
        # DRY RUN
        # =================================================

        if SOARExecutorService.is_dry_run():
            return {
                "success": True,
                "executed": False,
                "simulated": True,
                "mode": "dry_run",
                "action_type": "send_notification",
                "target": target,
                "message": (
                    f"DRY RUN: notification to "
                    f"{target} simulated successfully."
                ),
            }

        # =================================================
        # FEATURE FLAG
        # =================================================

        if not settings.SOAR_ENABLE_SEND_NOTIFICATION:
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "send_notification",
                "target": target,
                "message": (
                    "Real notifications are disabled by "
                    "SOAR_ENABLE_SEND_NOTIFICATION."
                ),
            }

        # =================================================
        # SELECT PROVIDER
        # =================================================

        normalized_target = target.strip().lower()

        slack_webhook_url = secret_manager.get(
            "SLACK_WEBHOOK_URL",
            "",
        )

        teams_webhook_url = secret_manager.get(
            "TEAMS_WEBHOOK_URL",
            "",
        )

        webhook_url = ""
        provider = ""

        if "slack" in normalized_target:
            webhook_url = slack_webhook_url
            provider = "slack"

        elif "teams" in normalized_target:
            webhook_url = teams_webhook_url
            provider = "teams"

        else:
            configured_webhooks = []

            if slack_webhook_url:
                configured_webhooks.append(
                    (
                        "slack",
                        slack_webhook_url,
                    )
                )

            if teams_webhook_url:
                configured_webhooks.append(
                    (
                        "teams",
                        teams_webhook_url,
                    )
                )

            if len(configured_webhooks) == 1:
                provider, webhook_url = configured_webhooks[0]

        if not webhook_url:
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "send_notification",
                "target": target,
                "message": (
                    "No Slack or Teams webhook is configured "
                    "for this notification target."
                ),
            }

        # =================================================
        # PAYLOAD
        # =================================================

        payload = {
            "text": (
                "AI-Powered SOC Analyst notification\n"
                f"Target: {target}\n"
                "A SOC response action requires attention."
            )
        }

        # =================================================
        # SEND WEBHOOK
        # =================================================

        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10,
            )

            response.raise_for_status()

        except requests.RequestException as exc:
            return {
                "success": False,
                "executed": False,
                "simulated": False,
                "mode": settings.SOAR_EXECUTION_MODE,
                "action_type": "send_notification",
                "target": target,
                "provider": provider,
                "message": (
                    "External SOC notification failed: "
                    f"{exc}"
                ),
            }

        return {
            "success": True,
            "executed": True,
            "simulated": False,
            "mode": settings.SOAR_EXECUTION_MODE,
            "action_type": "send_notification",
            "target": target,
            "provider": provider,
            "message": (
                f"SOC notification delivered successfully "
                f"through {provider}."
            ),
        }

    # =====================================================
    # NOTIFICATION TARGET VALIDATION
    # =====================================================

    @staticmethod
    def is_safe_notification_target(
        target: str,
    ) -> bool:
        """
        Reject unusable notification destinations.
        """

        if not target:
            return False

        normalized = target.strip().lower()

        unsafe_values = {
            "",
            "unknown",
            "unknown-target",
            "unknown_target",
            "none",
            "null",
            "n/a",
            "na",
            "undefined",
        }

        return normalized not in unsafe_values

    # =====================================================
    # IP VALIDATION
    # =====================================================

    @staticmethod
    def is_safe_ip(
        target: str,
    ) -> bool:
        """
        Reject invalid or protected IP addresses.
        """

        if not target:
            return False

        try:
            ip = ip_address(
                target.strip()
            )

        except ValueError:
            return False

        if ip.is_loopback:
            return False

        if ip.is_unspecified:
            return False

        if ip.is_multicast:
            return False

        return True

    # =====================================================
    # ENDPOINT VALIDATION
    # =====================================================

    @staticmethod
    def is_safe_endpoint(
        target: str,
    ) -> bool:
        """
        Reject unusable endpoint identifiers.
        """

        if not target:
            return False

        normalized = target.strip().lower()

        unsafe_values = {
            "",
            "unknown",
            "unknown-endpoint",
            "unknown_endpoint",
            "none",
            "null",
            "n/a",
            "na",
            "undefined",
        }

        return normalized not in unsafe_values