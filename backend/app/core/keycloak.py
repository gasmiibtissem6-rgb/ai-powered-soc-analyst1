from functools import lru_cache
from typing import Any, Dict, List

import jwt
from fastapi import HTTPException, status
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from app.core.config import settings


class KeycloakTokenValidator:
    def __init__(self) -> None:
        self.issuer = settings.KEYCLOAK_ISSUER
        self.audience = settings.KEYCLOAK_CLIENT_ID

        self.jwks_url = (
            f"{settings.KEYCLOAK_URL}/realms/"
            f"{settings.KEYCLOAK_REALM}/protocol/openid-connect/certs"
        )

        self.jwks_client = PyJWKClient(
            self.jwks_url
        )

    def decode_token(
        self,
        token: str,
    ) -> Dict[str, Any]:
        try:
            signing_key = (
                self.jwks_client
                .get_signing_key_from_jwt(token)
                .key
            )

            payload = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
            )

        except (InvalidTokenError, PyJWKClientError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Keycloak access token",
                headers={
                    "WWW-Authenticate": "Bearer",
                },
            ) from exc

        return payload

    def get_client_roles(
        self,
        payload: Dict[str, Any],
    ) -> List[str]:
        resource_access = payload.get(
            "resource_access",
            {}
        )

        client_access = resource_access.get(
            settings.KEYCLOAK_CLIENT_ID,
            {}
        )

        roles = client_access.get(
            "roles",
            []
        )

        if not isinstance(roles, list):
            return []

        return roles


@lru_cache
def get_keycloak_validator() -> KeycloakTokenValidator:
    return KeycloakTokenValidator()
