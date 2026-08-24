from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.report import SOCReport
from app.schemas.report import SOCReportCreate


class ReportService:

    # =====================================================
    # GET ALL REPORTS
    # =====================================================

    @staticmethod
    def get_reports(
        db: Session,
    ) -> List[SOCReport]:

        return (
            db.query(SOCReport)
            .order_by(SOCReport.id.desc())
            .all()
        )

    # =====================================================
    # GET ONE REPORT
    # =====================================================

    @staticmethod
    def get_report(
        db: Session,
        report_id: int,
    ) -> Optional[SOCReport]:

        return (
            db.query(SOCReport)
            .filter(SOCReport.id == report_id)
            .first()
        )

    # =====================================================
    # GET REPORTS BY INCIDENT
    # =====================================================

    @staticmethod
    def get_reports_by_incident(
        db: Session,
        incident_id: int,
    ) -> List[SOCReport]:

        return (
            db.query(SOCReport)
            .filter(SOCReport.incident_id == incident_id)
            .order_by(SOCReport.id.desc())
            .all()
        )

    # =====================================================
    # CREATE REPORT
    # =====================================================

    @staticmethod
    def create_report(
        db: Session,
        report_data: SOCReportCreate,
    ) -> SOCReport:

        report = SOCReport(
            **report_data.model_dump()
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        return report