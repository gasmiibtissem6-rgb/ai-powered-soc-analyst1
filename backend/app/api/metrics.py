from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.core.security import require_analyst
from app.models.user import User
from app.services.metrics_service import MetricsService


router = APIRouter(
    prefix="/metrics",
    tags=["metrics"],
)


@router.get("")
def get_soc_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return MetricsService.get_global_metrics(
        db
    )
