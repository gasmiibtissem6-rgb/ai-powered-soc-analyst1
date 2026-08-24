from typing import Optional
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from pydantic import BaseModel
from sqlalchemy.orm import Session

from langgraph.types import Command

from app.database.session import get_db
from app.models.incident import Incident
from app.agents.soc_graph import soc_graph


router = APIRouter(
    prefix="/agents",
    tags=["SOC Agents"],
)


# =========================================================
# HUMAN DECISION SCHEMA
# =========================================================

class HumanDecision(BaseModel):
    approved: bool
    comment: Optional[str] = None


# =========================================================
# START SOC WORKFLOW
# =========================================================

@router.post("/analyze/{incident_id}")
def analyze_incident_with_agents(
    incident_id: int,
    db: Session = Depends(get_db),
):

    # -----------------------------------------------------
    # 1. Charger l'incident depuis PostgreSQL
    # -----------------------------------------------------

    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    # -----------------------------------------------------
    # 2. Créer un thread unique LangGraph
    # -----------------------------------------------------

    thread_id = str(uuid4())

    config = {
        "configurable": {
            "thread_id": thread_id
        }
    }

    # -----------------------------------------------------
    # 3. Etat initial du workflow
    # -----------------------------------------------------

    initial_state = {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "source": incident.source,
        }
    }

    # -----------------------------------------------------
    # 4. Lancer LangGraph
    # -----------------------------------------------------

    try:

        result = soc_graph.invoke(
            initial_state,
            config=config,
        )

    except Exception as exc:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "SOC agents workflow failed: "
                f"{str(exc)}"
            ),
        )

    # -----------------------------------------------------
    # 5. Vérifier si LangGraph est interrompu
    # -----------------------------------------------------

    interrupts = result.get(
        "__interrupt__",
        [],
    )

    # =====================================================
    # HUMAN APPROVAL REQUIRED
    # =====================================================

    if interrupts:

        interrupt_values = []

        for item in interrupts:

            interrupt_values.append(
                item.value
            )

        return {
            "status": "waiting_for_human",

            "thread_id": thread_id,

            "interrupt": interrupt_values,

            "incident": result.get(
                "incident"
            ),

            "triage": result.get(
                "triage"
            ),

            "threat_intelligence": result.get(
                "threat_intelligence"
            ),

            "investigation": result.get(
                "investigation"
            ),

            "mitre_validation": result.get(
                "mitre_validation"
            ),
        }

    # =====================================================
    # NO HUMAN APPROVAL REQUIRED
    # =====================================================

    return {
        "status": "completed",

        "thread_id": thread_id,

        "incident": result.get(
            "incident"
        ),

        "triage": result.get(
            "triage"
        ),

        "threat_intelligence": result.get(
            "threat_intelligence"
        ),

        "investigation": result.get(
            "investigation"
        ),

        "mitre_validation": result.get(
            "mitre_validation"
        ),

        "human_review": result.get(
            "human_review"
        ),

        "response": result.get(
            "response"
        ),

        "report": result.get(
            "report"
        ),
    }


# =========================================================
# RESUME SOC WORKFLOW
# =========================================================

@router.post("/resume/{thread_id}")
def resume_soc_workflow(
    thread_id: str,
    decision: HumanDecision,
):

    config = {
        "configurable": {
            "thread_id": thread_id
        }
    }

    # -----------------------------------------------------
    # 1. Vérifier que le workflow existe toujours
    # -----------------------------------------------------

    try:

        snapshot = soc_graph.get_state(
            config
        )

    except Exception as exc:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Unable to read workflow state: "
                f"{str(exc)}"
            ),
        )

    # Pas de checkpoint trouvé
    if not snapshot.values:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Workflow not found. "
                "The in-memory checkpoint may have been "
                "lost after a server reload. "
                "Run /agents/analyze/{incident_id} again."
            ),
        )

    # -----------------------------------------------------
    # 2. Vérifier que l'incident existe encore dans le state
    # -----------------------------------------------------

    incident_state = snapshot.values.get(
        "incident"
    )

    if not incident_state:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Workflow state is incomplete: "
                "incident data is missing. "
                "Start a new analysis before resuming."
            ),
        )

    # -----------------------------------------------------
    # 3. Vérifier investigation
    # -----------------------------------------------------

    investigation_state = snapshot.values.get(
        "investigation"
    )

    if not investigation_state:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Workflow state is incomplete: "
                "investigation data is missing."
            ),
        )

    # -----------------------------------------------------
    # 4. Vérifier que le workflow attend bien une décision
    # -----------------------------------------------------

    if not snapshot.next:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This workflow is not waiting "
                "for human approval."
            ),
        )

    # -----------------------------------------------------
    # 5. Reprendre LangGraph
    # -----------------------------------------------------

    try:

        result = soc_graph.invoke(
            Command(
                resume={
                    "approved": decision.approved,
                    "comment": decision.comment,
                }
            ),
            config=config,
        )

    except Exception as exc:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Unable to resume workflow: "
                f"{str(exc)}"
            ),
        )

    # -----------------------------------------------------
    # 6. Vérifier que le workflow n'est pas encore interrompu
    # -----------------------------------------------------

    remaining_interrupts = result.get(
        "__interrupt__",
        [],
    )

    if remaining_interrupts:

        return {
            "status": "waiting_for_human",
            "thread_id": thread_id,
            "interrupt": [
                item.value
                for item in remaining_interrupts
            ],
        }

    # -----------------------------------------------------
    # 7. Résultat final
    # -----------------------------------------------------

    return {
        "status": "completed",

        "thread_id": thread_id,

        "incident": result.get(
            "incident"
        ),

        "triage": result.get(
            "triage"
        ),

        "threat_intelligence": result.get(
            "threat_intelligence"
        ),

        "investigation": result.get(
            "investigation"
        ),

        "mitre_validation": result.get(
            "mitre_validation"
        ),

        "human_review": result.get(
            "human_review"
        ),

        "response": result.get(
            "response"
        ),

        "report": result.get(
            "report"
        ),
    }