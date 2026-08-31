from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.soar_service import SOARService
from app.schemas.soar_action import (
    SOARActionCreate,
    SOARActionResponse,
    SOARActionLogResponse,
)
router = APIRouter(
    prefix="/soar",
    tags=["SOAR"],
)


@router.get("", response_model=list[SOARActionResponse])
def get_actions(db: Session = Depends(get_db)):
    return SOARService.get_actions(db)

@router.get(
    "/{action_id}/logs",
    response_model=list[SOARActionLogResponse],
)
def get_action_logs(
    action_id: int,
    db: Session = Depends(get_db),
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

@router.get("/{action_id}", response_model=SOARActionResponse)
def get_action(action_id: int, db: Session = Depends(get_db)):
    action = SOARService.get_action(db, action_id)

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    return action


@router.post(
    "",
    response_model=SOARActionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_action(
    data: SOARActionCreate,
    db: Session = Depends(get_db),
):
    action = SOARService.create_action(db, data)

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return action


@router.post("/{action_id}/approve", response_model=SOARActionResponse)
def approve_action(action_id: int, db: Session = Depends(get_db)):
    action = SOARService.approve_action(db, action_id)

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    return action


@router.post("/{action_id}/reject", response_model=SOARActionResponse)
def reject_action(action_id: int, db: Session = Depends(get_db)):
    action = SOARService.reject_action(db, action_id)

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    return action


@router.post("/{action_id}/execute", response_model=SOARActionResponse)
def execute_action(action_id: int, db: Session = Depends(get_db)):
    result = SOARService.execute_action(db, action_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOAR action not found",
        )

    if result == "approval_required":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Human approval is required before execution",
        )

    return result