from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from app.core.config import settings
from app.core.keycloak import KeycloakTokenValidator


def test_keycloak_decode_token_validates_issuer_and_audience(monkeypatch):
    validator = KeycloakTokenValidator()

    fake_signing_key = SimpleNamespace(key="fake-public-key")

    monkeypatch.setattr(
        validator.jwks_client,
        "get_signing_key_from_jwt",
        lambda token: fake_signing_key,
    )

    captured = {}

    def fake_decode(token, key, **kwargs):
        captured["token"] = token
        captured["key"] = key
        captured.update(kwargs)

        return {
            "sub": "keycloak-user-id",
            "iss": settings.KEYCLOAK_ISSUER,
            "aud": settings.KEYCLOAK_CLIENT_ID,
        }

    monkeypatch.setattr(
        "app.core.keycloak.jwt.decode",
        fake_decode,
    )

    payload = validator.decode_token("fake-token")

    assert payload["sub"] == "keycloak-user-id"
    assert captured["token"] == "fake-token"
    assert captured["key"] == "fake-public-key"
    assert captured["algorithms"] == ["RS256"]
    assert captured["issuer"] == settings.KEYCLOAK_ISSUER
    assert captured["audience"] == settings.KEYCLOAK_CLIENT_ID


def test_keycloak_client_roles_are_extracted():
    validator = KeycloakTokenValidator()

    payload = {
        "resource_access": {
            settings.KEYCLOAK_CLIENT_ID: {
                "roles": ["analyst", "admin"],
            }
        }
    }

    assert validator.get_client_roles(payload) == [
        "analyst",
        "admin",
    ]


def test_keycloak_missing_client_roles_returns_empty_list():
    validator = KeycloakTokenValidator()

    assert validator.get_client_roles({}) == []


def test_keycloak_invalid_token_returns_401(monkeypatch):
    validator = KeycloakTokenValidator()

    def raise_invalid_token(token):
        raise PyJWKClientError("invalid signing key")

    monkeypatch.setattr(
        validator.jwks_client,
        "get_signing_key_from_jwt",
        raise_invalid_token,
    )

    with pytest.raises(HTTPException) as exc_info:
        validator.decode_token("invalid-token")

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid Keycloak access token"
