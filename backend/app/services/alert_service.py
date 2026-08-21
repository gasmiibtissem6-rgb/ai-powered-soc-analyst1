from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertUpdate


class AlertService:

    @staticmethod
    def create_alert(db: Session, alert_data: AlertCreate) -> Alert:
        alert = Alert(**alert_data.model_dump())

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

    @staticmethod
    def get_alerts(db: Session):
        return db.query(Alert).order_by(Alert.created_at.desc()).all()

    @staticmethod
    def get_alert(db: Session, alert_id: int):
        return db.query(Alert).filter(Alert.id == alert_id).first()

    @staticmethod
    def update_alert(
        db: Session,
        alert_id: int,
        alert_data: AlertUpdate,
    ):
        alert = db.query(Alert).filter(Alert.id == alert_id).first()

        if not alert:
            return None

        update_data = alert_data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            setattr(alert, field, value)

        db.commit()
        db.refresh(alert)

        return alert

    @staticmethod
    def delete_alert(db: Session, alert_id: int) -> bool:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()

        if not alert:
            return False

        db.delete(alert)
        db.commit()

        return True