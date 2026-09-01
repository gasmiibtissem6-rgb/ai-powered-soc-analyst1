from typing import List

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

from app.core.security import require_analyst
from app.database.session import get_db
from app.models.user import User
from app.schemas.report import SOCReportResponse
from app.services.report_service import ReportService


router = APIRouter(
    prefix="/reports",
    tags=["SOC Reports"],
)


# =========================================================
# GET ALL REPORTS
# Analyst + Admin
# =========================================================

@router.get(
    "",
    response_model=List[SOCReportResponse],
)
def get_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return ReportService.get_reports(db)


# =========================================================
# GET REPORTS BY INCIDENT
# Analyst + Admin
# =========================================================

@router.get(
    "/incident/{incident_id}",
    response_model=List[SOCReportResponse],
)
def get_reports_by_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return ReportService.get_reports_by_incident(
        db,
        incident_id,
    )


# =========================================================
# GET ONE REPORT
# Analyst + Admin
# =========================================================

@router.get(
    "/{report_id}",
    response_model=SOCReportResponse,
)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    report = ReportService.get_report(
        db,
        report_id,
    )

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOC report not found",
        )

    return report