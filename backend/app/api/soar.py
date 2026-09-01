from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import require_admin, require_analyst
from app.database.session import get_db
from app.models.user import User
from app.schemas.soar_action import (
    SOARActionCreate,
    SOARActionLogResponse,
    SOARActionResponse,
)
from app.services.soar_service import SOARService


router = APIRouter(
    prefix="/soar",
    tags=["SOAR"],
)


# =========================================================
# GET ALL SOAR ACTIONS
# Analyst + Admin
# =========================================================

@router.get(
    "",
    response_model=list[SOARActionResponse],
)
def get_actions(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return SOARService.get_actions(db)


# =========================================================
# GET SOAR ACTION LOGS
# Analyst + Admin
# =========================================================

@router.get(
    "/{action_id}/logs",
    response_model=list[SOARActionLogResponse],
)
def get_action_logs(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    logs = SOARService.get_action_logs(
        db=db,
        action_id=action_id,
    )

    if logs is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    return logs


# =========================================================
# GET ONE SOAR ACTION
# Analyst + Admin
# =========================================================

@router.get(
    "/{action_id}",
    response_model=SOARActionResponse,
)
def get_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    action = SOARService.get_action(
        db,
        action_id,
    )

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    return action


# =========================================================
# CREATE / PROPOSE SOAR ACTION
# Analyst + Admin
# =========================================================

@router.post(
    "",
    response_model=SOARActionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_action(
    data: SOARActionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    action = SOARService.create_action(
        db,
        data,
    )

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return action


# =========================================================
# APPROVE SOAR ACTION
# Admin only
# =========================================================

@router.post(
    "/{action_id}/approve",
    response_model=SOARActionResponse,
)
def approve_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    action = SOARService.approve_action(
        db,
        action_id,
    )

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    return action


# =========================================================
# REJECT SOAR ACTION
# Admin only
# =========================================================

@router.post(
    "/{action_id}/reject",
    response_model=SOARActionResponse,
)
def reject_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    action = SOARService.reject_action(
        db,
        action_id,
    )

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    return action


# =========================================================
# EXECUTE SOAR ACTION
# Admin only
# =========================================================

@router.post(
    "/{action_id}/execute",
    response_model=SOARActionResponse,
)
def execute_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = SOARService.execute_action(
        db,
        action_id,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    if result == "approval_required":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Human approval is required "
                "before execution"
            ),
        )

    return result