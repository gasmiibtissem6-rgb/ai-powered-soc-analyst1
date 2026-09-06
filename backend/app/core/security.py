from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Union

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
import bcrypt
from sqlalchemy.orm import Session
from app.core.secrets import secret_manager
from app.core.config import settings
from app.database.session import get_db
from app.models.user import User
from app.core.auth_principal import AuthPrincipal
from app.core.keycloak import get_keycloak_validator



bearer_scheme = HTTPBearer(
    auto_error=False,
)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta
        if expires_delta is not None
        else timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    payload = {
        "sub": str(subject),
        "exp": expire,
    }

    return jwt.encode(
        payload,
        secret_manager.get("SECRET_KEY"),
        algorithm=settings.ALGORITHM,
    )


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            secret_manager.get("SECRET_KEY"),
            algorithms=[settings.ALGORITHM],
        )
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc

    subject = payload.get("sub")

    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return payload
def decode_any_access_token(
    token: str,
) -> AuthPrincipal:
    try:
        payload = decode_access_token(token)

        return AuthPrincipal(
            subject=str(payload["sub"]),
            roles=[],
            source="internal",
        )

    except HTTPException:
        validator = get_keycloak_validator()
        payload = validator.decode_token(token)

        roles = validator.get_client_roles(
            payload
        )

        return AuthPrincipal(
            subject=str(payload["sub"]),
            roles=roles,
            source="keycloak",
            email=payload.get("email"),
            full_name=payload.get(
                "name"
            ),
        )

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    payload = decode_access_token(
        credentials.credentials
    )

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token subject",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    return user
def get_current_principal(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> AuthPrincipal:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    principal = decode_any_access_token(
        credentials.credentials
    )

    # Keycloak user: roles are already contained
    # in the Keycloak access token.
    if principal.source == "keycloak":
        return principal

    # Internal JWT: load the local PostgreSQL user
    # to recover its RBAC role.
    try:
        user_id = int(principal.subject)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token subject",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    return AuthPrincipal(
        subject=str(user.id),
        roles=[user.role],
        source="internal",
        email=user.email,
        full_name=user.full_name,
    )

def require_roles(
    allowed_roles: List[str],
):
    def dependency(
        current_user: AuthPrincipal = Depends(
            get_current_principal
        ),
    ) -> AuthPrincipal:
        roles = getattr(
            current_user,
            "roles",
            None,
        )

        if roles is None:
            single_role = getattr(
                current_user,
                "role",
                None,
            )

            roles = (
                [single_role]
                if single_role
                else []
            )

        if not any(
            role in roles
            for role in allowed_roles
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return current_user

    return dependency

def require_analyst(
    current_user: AuthPrincipal = Depends(
        require_roles(
            [
                "analyst",
                "admin",
            ]
        )
    ),
) -> AuthPrincipal:
    return current_user


def require_admin(
    current_user: AuthPrincipal = Depends(
        require_roles(
            [
                "admin",
            ]
        )
    ),
) -> AuthPrincipal:
    return current_user