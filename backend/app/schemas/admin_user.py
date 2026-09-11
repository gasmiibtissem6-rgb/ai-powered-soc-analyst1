from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


class AdminUserResponse(BaseModel):
    id: str
    username: str

    # Keycloak may contain internal/local development
    # addresses such as admin@soc.local.
    # Keep the response permissive while validating
    # newly created accounts separately.
    email: Optional[str] = None

    first_name: Optional[str] = None
    last_name: Optional[str] = None
    enabled: bool
    roles: List[str]


class AdminUserCreate(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=100,
    )

    email: EmailStr

    first_name: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    last_name: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    password: str = Field(
        min_length=8,
        max_length=128,
    )

    roles: List[str] = [
        "analyst",
    ]

    enabled: bool = True


class AdminUserEnabledUpdate(BaseModel):
    enabled: bool


class AdminUserRolesUpdate(BaseModel):
    roles: List[str]


class AdminUserPasswordUpdate(BaseModel):
    password: str = Field(
        min_length=8,
        max_length=128,
    )

    temporary: bool = False

    