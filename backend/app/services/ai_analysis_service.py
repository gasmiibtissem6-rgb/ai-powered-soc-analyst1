from sqlalchemy.orm import Session

from app.models.ai_analysis import AIAnalysis
from app.models.incident import Incident
from app.schemas.ai_analysis import AIAnalysisCreate, AIAnalysisUpdate


class AIAnalysisService:

    @staticmethod
    def get_analyses(db: Session):
        return db.query(AIAnalysis).order_by(
            AIAnalysis.id.desc()
        ).all()

    @staticmethod
    def get_analysis(db: Session, analysis_id: int):
        return db.query(AIAnalysis).filter(
            AIAnalysis.id == analysis_id
        ).first()

    @staticmethod
    def create_analysis(
        db: Session,
        analysis_data: AIAnalysisCreate,
    ):
        incident = db.query(Incident).filter(
            Incident.id == analysis_data.incident_id
        ).first()

        if not incident:
            return None

        analysis = AIAnalysis(
            **analysis_data.model_dump()
        )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        return analysis

    @staticmethod
    def update_analysis(
        db: Session,
        analysis_id: int,
        analysis_data: AIAnalysisUpdate,
    ):
        analysis = db.query(AIAnalysis).filter(
            AIAnalysis.id == analysis_id
        ).first()

        if not analysis:
            return None

        update_data = analysis_data.model_dump(
            exclude_unset=True
        )

        for key, value in update_data.items():
            setattr(analysis, key, value)

        db.commit()
        db.refresh(analysis)

        return analysis

    @staticmethod
    def delete_analysis(
        db: Session,
        analysis_id: int,
    ) -> bool:
        analysis = db.query(AIAnalysis).filter(
            AIAnalysis.id == analysis_id
        ).first()

        if not analysis:
            return False

        db.delete(analysis)
        db.commit()

        return True