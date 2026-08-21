from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.models.user import User


class AuthService:

    @staticmethod
    def register(
        db: Session,
        full_name: str,
        email: str,
        password: str,
    ) -> User:
        existing_user = (
            db.query(User)
            .filter(User.email == email)
            .first()
        )

        if existing_user:
            raise ValueError("Email already exists")

        user = User(
            full_name=full_name,
            email=email,
            hashed_password=hash_password(password),
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return user

    @staticmethod
    def login(
        db: Session,
        email: str,
        password: str,
    ):
        user = (
            db.query(User)
            .filter(User.email == email)
            .first()
        )

        if not user:
            return None

        if not user.is_active:
            return None

        if not verify_password(
            password,
            user.hashed_password,
        ):
            return None

        token = create_access_token(str(user.id))

        return {
            "access_token": token,
            "token_type": "bearer",
        }