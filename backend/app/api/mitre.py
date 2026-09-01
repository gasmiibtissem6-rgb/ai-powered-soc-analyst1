from fastapi import APIRouter, Depends

from app.core.security import require_analyst
from app.models.user import User
from app.services.mitre_service import MitreService


router = APIRouter(
    prefix="/mitre",
    tags=["MITRE ATT&CK"],
)

service = MitreService()


@router.get("/technique/{technique_id}")
def validate_technique(
    technique_id: str,
    current_user: User = Depends(require_analyst),
):
    return service.validate_technique(
        technique_id
    )