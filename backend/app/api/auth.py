from fastapi import APIRouter, Depends, HTTPException, Request, status
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
from app.services.audit_service import AuditService
from app.models.user import User


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
    request: Request,
    db: Session = Depends(get_db),
    current_user: AuthPrincipal = Depends(require_admin),
):
    """
    Create a new SOC analyst account.

    Only administrators are allowed to create users.
    Newly created accounts receive the analyst role.
    """
    try:
        user = AuthService.register(
            db=db,
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
        )

        AuditService.log_event(
            db,
            event_type="auth.user_registered",
            outcome="success",
            actor_subject=current_user.subject,
            actor_source=current_user.source,
            actor_email=current_user.email,
            resource_type="user",
            resource_id=str(user.id),
            request_method=request.method,
            request_path=request.url.path,
            client_ip=(
                request.client.host
                if request.client
                else None
            ),
            details={
                "created_user_email": user.email,
                "created_user_role": user.role,
            },
        )

        return user

    except ValueError as error:
        AuditService.log_event(
            db,
            event_type="auth.user_registration_failed",
            outcome="failure",
            actor_subject=current_user.subject,
            actor_source=current_user.source,
            actor_email=current_user.email,
            resource_type="user",
            request_method=request.method,
            request_path=request.url.path,
            client_ip=(
                request.client.host
                if request.client
                else None
            ),
            details={
                "target_email": payload.email,
                "reason": str(error),
            },
        )

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
    request: Request,
    db: Session = Depends(get_db),
):
    result = AuthService.login(
        db=db,
        email=payload.email,
        password=payload.password,
    )

    if result is None:
        AuditService.log_event(
            db,
            event_type="auth.login_failed",
            outcome="failure",
            actor_source="internal",
            actor_email=payload.email,
            request_method=request.method,
            request_path=request.url.path,
            client_ip=(
                request.client.host
                if request.client
                else None
            ),
            details={
                "reason": "invalid_credentials_or_inactive_user",
            },
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    user = (
        db.query(User)
        .filter(User.email == payload.email)
        .first()
    )

    AuditService.log_event(
        db,
        event_type="auth.login_success",
        outcome="success",
        actor_subject=(
            str(user.id)
            if user
            else None
        ),
        actor_source="internal",
        actor_email=payload.email,
        resource_type="session",
        request_method=request.method,
        request_path=request.url.path,
        client_ip=(
            request.client.host
            if request.client
            else None
        ),
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
