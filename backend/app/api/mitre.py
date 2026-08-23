from fastapi import APIRouter

from app.services.mitre_service import MitreService


router = APIRouter(
    prefix="/mitre",
    tags=["MITRE ATT&CK"],
)

service = MitreService()


@router.get("/technique/{technique_id}")
def validate_technique(technique_id: str):
    return service.validate_technique(technique_id)