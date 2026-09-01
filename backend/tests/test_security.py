from datetime import timedelta

import jwt
import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    require_admin,
    require_analyst,
    require_roles,
    verify_password,
)


class FakeUser:
    def __init__(self, role: str):
        self.role = role
        self.is_active = True


def test_password_hash_and_verify():
    password = "StrongPassword123!"

    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_create_and_decode_access_token():
    token = create_access_token("123")

    payload = decode_access_token(token)

    assert payload["sub"] == "123"
    assert "exp" in payload


def test_expired_access_token_is_rejected():
    token = create_access_token(
        "123",
        expires_delta=timedelta(seconds=-1),
    )

    with pytest.raises(HTTPException) as exc:
        decode_access_token(token)

    assert exc.value.status_code == 401
    assert (
        exc.value.detail
        == "Invalid or expired access token"
    )


def test_invalid_access_token_is_rejected():
    with pytest.raises(HTTPException) as exc:
        decode_access_token(
            "this-is-not-a-valid-jwt"
        )

    assert exc.value.status_code == 401
    assert (
        exc.value.detail
        == "Invalid or expired access token"
    )


def test_token_without_subject_is_rejected():
    token = jwt.encode(
        {},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    with pytest.raises(HTTPException) as exc:
        decode_access_token(token)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid access token"


def test_require_roles_accepts_analyst():
    dependency = require_roles(
        ["analyst", "admin"]
    )

    user = FakeUser("analyst")

    result = dependency(
        current_user=user
    )

    assert result is user


def test_require_roles_accepts_admin():
    dependency = require_roles(
        ["analyst", "admin"]
    )

    user = FakeUser("admin")

    result = dependency(
        current_user=user
    )

    assert result is user


def test_require_roles_rejects_unauthorized_role():
    dependency = require_roles(
        ["admin"]
    )

    user = FakeUser("analyst")

    with pytest.raises(HTTPException) as exc:
        dependency(
            current_user=user
        )

    assert exc.value.status_code == 403
    assert (
        exc.value.detail
        == "Insufficient permissions"
    )


def test_require_analyst_accepts_analyst():
    user = FakeUser("analyst")

    result = require_analyst(
        current_user=user
    )

    assert result is user


def test_require_admin_accepts_admin():
    user = FakeUser("admin")

    result = require_admin(
        current_user=user
    )

    assert result is user


class FakeQuery:
    def __init__(self, user):
        self.user = user

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.user


class FakeDB:
    def __init__(self, user=None):
        self.user = user

    def query(self, *args, **kwargs):
        return FakeQuery(self.user)


class FakeCredentials:
    def __init__(self, token):
        self.credentials = token


def test_get_current_user_requires_credentials():
    from app.core.security import get_current_user

    with pytest.raises(HTTPException) as exc:
        get_current_user(
            credentials=None,
            db=FakeDB(),
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "Authentication required"


def test_get_current_user_rejects_unknown_user():
    from app.core.security import get_current_user

    token = create_access_token("999")

    with pytest.raises(HTTPException) as exc:
        get_current_user(
            credentials=FakeCredentials(token),
            db=FakeDB(user=None),
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "User not found"


def test_get_current_user_rejects_disabled_user():
    from app.core.security import get_current_user

    user = FakeUser("analyst")
    user.id = 123
    user.is_active = False

    token = create_access_token("123")

    with pytest.raises(HTTPException) as exc:
        get_current_user(
            credentials=FakeCredentials(token),
            db=FakeDB(user=user),
        )

    assert exc.value.status_code == 403
    assert exc.value.detail == "User account is disabled"


def test_get_current_user_accepts_active_user():
    from app.core.security import get_current_user

    user = FakeUser("analyst")
    user.id = 123
    user.is_active = True

    token = create_access_token("123")

    result = get_current_user(
        credentials=FakeCredentials(token),
        db=FakeDB(user=user),
    )

    assert result is user
