from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth_principal import AuthPrincipal
from app.core.security import get_current_principal, require_admin
from app.database.session import get_db
from app.schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth_service import AuthService


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
    current_user: AuthPrincipal = Depends(require_admin),
):
    """
    Create a new SOC analyst account.

    Only administrators are allowed to create users.
    Newly created accounts receive the analyst role.
    """
    try:
        return AuthService.register(
            db=db,
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    result = AuthService.login(
        db=db,
        email=payload.email,
        password=payload.password,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return result


@router.get(
    "/me",
    response_model=CurrentUserResponse,
)
def get_me(
    current_user: AuthPrincipal = Depends(
        get_current_principal
    ),
):
    return CurrentUserResponse(
        subject=current_user.subject,
        email=current_user.email,
        full_name=current_user.full_name,
        roles=current_user.roles,
        source=current_user.source,
    )
