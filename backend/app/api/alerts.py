from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import require_admin, require_analyst
from app.database.session import get_db
from app.models.user import User
from app.schemas.alert import AlertCreate, AlertResponse, AlertUpdate
from app.services.alert_service import AlertService


router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
)


@router.post(
    "",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_alert(
    alert_data: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return AlertService.create_alert(
        db,
        alert_data,
    )


@router.get(
    "",
    response_model=List[AlertResponse],
)
def get_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return AlertService.get_alerts(db)


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    alert = AlertService.get_alert(
        db,
        alert_id,
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return alert


@router.put(
    "/{alert_id}",
    response_model=AlertResponse,
)
def update_alert(
    alert_id: int,
    alert_data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    alert = AlertService.update_alert(
        db,
        alert_id,
        alert_data,
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return alert


@router.delete(
    "/{alert_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    deleted = AlertService.delete_alert(
        db,
        alert_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return None