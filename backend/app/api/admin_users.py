import requests

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from app.core.security import require_admin
from app.core.auth_principal import AuthPrincipal
from app.schemas.admin_user import (
    AdminUserCreate,
    AdminUserEnabledUpdate,
    AdminUserPasswordUpdate,
    AdminUserResponse,
    AdminUserRolesUpdate,
)
from app.services.keycloak_admin_service import (
    KeycloakAdminService,
)


router = APIRouter(
    prefix="/admin/users",
    tags=["Admin Users"],
)


def get_service():
    try:
        return KeycloakAdminService()

    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


def translate_keycloak_error(
    exc: requests.HTTPError,
) -> HTTPException:
    response = exc.response

    if response is None:
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Keycloak administration request failed",
        )

    if response.status_code == 404:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Keycloak user not found",
        )

    if response.status_code == 409:
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "A Keycloak user with the same "
                "username or email already exists"
            ),
        )

    if response.status_code in {
        401,
        403,
    }:
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Keycloak admin service account "
                "is not authorized"
            ),
        )

    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Keycloak administration request failed",
    )


@router.get(
    "",
    response_model=list[AdminUserResponse],
)
def list_users(
    current_user: AuthPrincipal = Depends(
        require_admin
    ),
):
    service = get_service()

    try:
        return service.list_users()

    except requests.HTTPError as exc:
        raise translate_keycloak_error(
            exc
        ) from exc


@router.post(
    "",
    response_model=AdminUserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: AdminUserCreate,
    current_user: AuthPrincipal = Depends(
        require_admin
    ),
):
    service = get_service()

    try:
        return service.create_user(
            username=payload.username,
            email=str(
                payload.email
            ),
            first_name=(
                payload.first_name
            ),
            last_name=(
                payload.last_name
            ),
            password=payload.password,
            roles=payload.roles,
            enabled=payload.enabled,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except requests.HTTPError as exc:
        raise translate_keycloak_error(
            exc
        ) from exc


@router.put(
    "/{user_id}/enabled",
    response_model=AdminUserResponse,
)
def update_enabled(
    user_id: str,
    payload: AdminUserEnabledUpdate,
    current_user: AuthPrincipal = Depends(
        require_admin
    ),
):
    service = get_service()

    try:
        return service.set_enabled(
            user_id=user_id,
            enabled=payload.enabled,
        )

    except requests.HTTPError as exc:
        raise translate_keycloak_error(
            exc
        ) from exc


@router.put(
    "/{user_id}/roles",
    response_model=AdminUserResponse,
)
def update_roles(
    user_id: str,
    payload: AdminUserRolesUpdate,
    current_user: AuthPrincipal = Depends(
        require_admin
    ),
):
    service = get_service()

    try:
        return service.set_user_roles(
            user_id=user_id,
            roles=payload.roles,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except requests.HTTPError as exc:
        raise translate_keycloak_error(
            exc
        ) from exc


@router.put(
    "/{user_id}/password",
    status_code=status.HTTP_204_NO_CONTENT,
)
def update_password(
    user_id: str,
    payload: AdminUserPasswordUpdate,
    current_user: AuthPrincipal = Depends(
        require_admin
    ),
):
    service = get_service()

    try:
        service.reset_password(
            user_id=user_id,
            password=payload.password,
            temporary=payload.temporary,
        )

    except requests.HTTPError as exc:
        raise translate_keycloak_error(
            exc
        ) from exc

    return None


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_user(
    user_id: str,
    current_user: AuthPrincipal = Depends(
        require_admin
    ),
):
    service = get_service()

    try:
        service.delete_user(
            user_id
        )

    except requests.HTTPError as exc:
        raise translate_keycloak_error(
            exc
        ) from exc

    return None