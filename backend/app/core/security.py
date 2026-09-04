from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Union

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.core.secrets import secret_manager
from app.core.config import settings
from app.database.session import get_db
from app.models.user import User


password_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

bearer_scheme = HTTPBearer(
    auto_error=False,
)


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return password_context.verify(
        plain_password,
        hashed_password,
    )


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


def require_roles(
    allowed_roles: List[str],
):
    def dependency(
        current_user: User = Depends(
            get_current_user
        ),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Insufficient permissions"
                ),
            )

        return current_user

    return dependency


def require_analyst(
    current_user: User = Depends(
        require_roles(
            [
                "analyst",
                "admin",
            ]
        )
    ),
) -> User:
    return current_user


def require_admin(
    current_user: User = Depends(
        require_roles(
            [
                "admin",
            ]
        )
    ),
) -> User:
    return current_user