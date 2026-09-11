from typing import Any, Dict, List

import requests

from app.core.config import settings


class KeycloakAdminService:
    """
    Administrative Keycloak client used by the SOC backend.

    Authentication:
    - OAuth2 client_credentials
    - soc-admin-service service account

    The service account is limited to the required
    realm-management user administration permissions.
    """

    def __init__(self) -> None:
        self.base_url = settings.KEYCLOAK_URL.rstrip("/")
        self.realm = settings.KEYCLOAK_REALM

        self.client_id = (
            settings.KEYCLOAK_ADMIN_CLIENT_ID
        )

        self.client_secret = (
            settings.KEYCLOAK_ADMIN_CLIENT_SECRET
        )

        self.soc_backend_client_id = (
            settings.KEYCLOAK_CLIENT_ID
        )

        if not self.client_id:
            raise RuntimeError(
                "KEYCLOAK_ADMIN_CLIENT_ID is not configured"
            )

        if not self.client_secret:
            raise RuntimeError(
                "KEYCLOAK_ADMIN_CLIENT_SECRET is not configured"
            )

    # =====================================================
    # ADMIN TOKEN
    # =====================================================

    def _get_admin_token(self) -> str:
        url = (
            f"{self.base_url}/realms/{self.realm}"
            "/protocol/openid-connect/token"
        )

        response = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=15,
        )

        response.raise_for_status()

        payload = response.json()

        token = payload.get(
            "access_token"
        )

        if not token:
            raise RuntimeError(
                "Keycloak did not return an admin access token"
            )

        return token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization":
                f"Bearer {self._get_admin_token()}",
            "Content-Type":
                "application/json",
        }

    # =====================================================
    # CLIENT LOOKUP
    # =====================================================

    def _get_soc_backend_client_uuid(
        self,
    ) -> str:
        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/clients"
        )

        response = requests.get(
            url,
            headers=self._headers(),
            params={
                "clientId":
                    self.soc_backend_client_id,
            },
            timeout=15,
        )

        response.raise_for_status()

        clients = response.json()

        if not clients:
            raise RuntimeError(
                "soc-backend Keycloak client not found"
            )

        return clients[0]["id"]

    # =====================================================
    # AVAILABLE SOC ROLES
    # =====================================================

    def _get_available_soc_roles(
        self,
    ) -> Dict[str, dict]:
        client_uuid = (
            self._get_soc_backend_client_uuid()
        )

        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/clients/"
            f"{client_uuid}/roles"
        )

        response = requests.get(
            url,
            headers=self._headers(),
            timeout=15,
        )

        response.raise_for_status()

        return {
            item["name"]: item
            for item in response.json()
            if item.get("name")
            in {
                "admin",
                "analyst",
            }
        }

    # =====================================================
    # USER ROLE LOOKUP
    # =====================================================

    def get_user_roles(
        self,
        user_id: str,
    ) -> List[str]:
        client_uuid = (
            self._get_soc_backend_client_uuid()
        )

        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/users/"
            f"{user_id}/role-mappings/clients/"
            f"{client_uuid}"
        )

        response = requests.get(
            url,
            headers=self._headers(),
            timeout=15,
        )

        response.raise_for_status()

        return [
            item["name"]
            for item in response.json()
            if item.get("name")
            in {
                "admin",
                "analyst",
            }
        ]

    # =====================================================
    # LIST USERS
    # =====================================================

    def list_users(
        self,
    ) -> List[Dict[str, Any]]:
        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/users"
        )

        response = requests.get(
            url,
            headers=self._headers(),
            params={
                "briefRepresentation":
                    "false",
            },
            timeout=15,
        )

        response.raise_for_status()

        users = []

        for item in response.json():
            username = (
                item.get("username")
                or ""
            )

            # Do not expose internal service-account users.
            if username.startswith(
                "service-account-"
            ):
                continue

            user_id = item["id"]

            users.append({
                "id": user_id,
                "username": username,
                "email": item.get(
                    "email"
                ),
                "first_name": item.get(
                    "firstName"
                ),
                "last_name": item.get(
                    "lastName"
                ),
                "enabled": bool(
                    item.get(
                        "enabled",
                        False,
                    )
                ),
                "roles":
                    self.get_user_roles(
                        user_id
                    ),
            })

        return users

    # =====================================================
    # CREATE USER
    # =====================================================

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        first_name: str | None = None,
        last_name: str | None = None,
        roles: List[str] | None = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        roles = roles or [
            "analyst",
        ]

        self._validate_roles(
            roles
        )

        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/users"
        )

        payload = {
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "emailVerified": False,
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False,
                }
            ],
        }

        response = requests.post(
            url,
            headers=self._headers(),
            json=payload,
            timeout=15,
        )

        response.raise_for_status()

        location = response.headers.get(
            "Location"
        )

        if not location:
            raise RuntimeError(
                "Keycloak did not return created user location"
            )

        user_id = (
            location.rstrip("/")
            .split("/")[-1]
        )

        self.set_user_roles(
            user_id,
            roles,
        )

        return self.get_user(
            user_id
        )

    # =====================================================
    # GET ONE USER
    # =====================================================

    def get_user(
        self,
        user_id: str,
    ) -> Dict[str, Any]:
        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/users/"
            f"{user_id}"
        )

        response = requests.get(
            url,
            headers=self._headers(),
            timeout=15,
        )

        response.raise_for_status()

        item = response.json()

        return {
            "id": item["id"],
            "username": item.get(
                "username",
                "",
            ),
            "email": item.get(
                "email"
            ),
            "first_name": item.get(
                "firstName"
            ),
            "last_name": item.get(
                "lastName"
            ),
            "enabled": bool(
                item.get(
                    "enabled",
                    False,
                )
            ),
            "roles":
                self.get_user_roles(
                    user_id
                ),
        }

    # =====================================================
    # ENABLE / DISABLE
    # =====================================================

    def set_enabled(
        self,
        user_id: str,
        enabled: bool,
    ) -> Dict[str, Any]:
        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/users/"
            f"{user_id}"
        )

        current_response = (
            requests.get(
                url,
                headers=self._headers(),
                timeout=15,
            )
        )

        current_response.raise_for_status()

        payload = (
            current_response.json()
        )

        payload["enabled"] = enabled

        response = requests.put(
            url,
            headers=self._headers(),
            json=payload,
            timeout=15,
        )

        response.raise_for_status()

        return self.get_user(
            user_id
        )

    # =====================================================
    # ROLES
    # =====================================================

    @staticmethod
    def _validate_roles(
        roles: List[str],
    ) -> None:
        allowed = {
            "admin",
            "analyst",
        }

        invalid = (
            set(roles)
            - allowed
        )

        if invalid:
            raise ValueError(
                "Unsupported SOC role(s): "
                + ", ".join(
                    sorted(
                        invalid
                    )
                )
            )

        if not roles:
            raise ValueError(
                "At least one SOC role is required"
            )

    def set_user_roles(
        self,
        user_id: str,
        roles: List[str],
    ) -> Dict[str, Any]:
        self._validate_roles(
            roles
        )

        client_uuid = (
            self._get_soc_backend_client_uuid()
        )

        available_roles = (
            self._get_available_soc_roles()
        )

        mapping_url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/users/"
            f"{user_id}/role-mappings/clients/"
            f"{client_uuid}"
        )

        current_response = (
            requests.get(
                mapping_url,
                headers=self._headers(),
                timeout=15,
            )
        )

        current_response.raise_for_status()

        current_roles = [
            item
            for item in current_response.json()
            if item.get("name")
            in {
                "admin",
                "analyst",
            }
        ]

        if current_roles:
            delete_response = (
                requests.delete(
                    mapping_url,
                    headers=self._headers(),
                    json=current_roles,
                    timeout=15,
                )
            )

            delete_response.raise_for_status()

        requested_roles = [
            available_roles[role]
            for role in roles
            if role in available_roles
        ]

        if (
            len(requested_roles)
            != len(roles)
        ):
            raise RuntimeError(
                "Required SOC client role is missing in Keycloak"
            )

        add_response = requests.post(
            mapping_url,
            headers=self._headers(),
            json=requested_roles,
            timeout=15,
        )

        add_response.raise_for_status()

        return self.get_user(
            user_id
        )

    # =====================================================
    # PASSWORD
    # =====================================================

    def reset_password(
        self,
        user_id: str,
        password: str,
        temporary: bool = False,
    ) -> None:
        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/users/"
            f"{user_id}/reset-password"
        )

        response = requests.put(
            url,
            headers=self._headers(),
            json={
                "type": "password",
                "value": password,
                "temporary": temporary,
            },
            timeout=15,
        )

        response.raise_for_status()

    # =====================================================
    # DELETE
    # =====================================================

    def delete_user(
        self,
        user_id: str,
    ) -> None:
        url = (
            f"{self.base_url}/admin/realms/"
            f"{self.realm}/users/"
            f"{user_id}"
        )

        response = requests.delete(
            url,
            headers=self._headers(),
            timeout=15,
        )

        response.raise_for_status()