from typing import Dict, Optional
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from langgraph.types import Command
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.agents.soc_graph import soc_graph
from app.core.config import settings
from app.database.session import get_db

from app.models.ai_analysis import AIAnalysis
from app.models.incident import Incident
from app.models.report import SOCReport
from app.models.soar_action import SOARAction


# =========================================================
# ROUTER
# =========================================================

router = APIRouter(
    prefix="/agents",
    tags=["SOC Agents"],
)


# =========================================================
# REQUEST SCHEMAS
# =========================================================

class HumanDecision(BaseModel):
    approved: bool
    comment: Optional[str] = None


class AnalyzeIncidentRequest(BaseModel):
    ml_features: Optional[Dict[str, float]] = None


# =========================================================
# WORKFLOW STATUS HELPER
# =========================================================

def update_incident_workflow_status(
    db: Session,
    incident: Incident,
    workflow_status: str,
    workflow_error: Optional[str] = None,
) -> None:
    """
    Persist the current SOC workflow state on the incident.
    """

    incident.workflow_status = workflow_status
    incident.workflow_error = workflow_error

    try:
        db.commit()
        db.refresh(incident)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Unable to update incident workflow status: "
                f"{str(exc)}"
            ),
        )


# =========================================================
# WORKFLOW ERROR CLASSIFICATION
# =========================================================

def is_llm_rate_limit_error(exc: Exception) -> bool:
    """
    Detect a temporary LLM/Groq rate-limit error.
    """

    error_text = str(exc).lower()

    indicators = [
        "llm_rate_limited",
        "rate_limit_exceeded",
        "rate limit reached",
        "error code: 429",
        "too many requests",
    ]

    return any(
        indicator in error_text
        for indicator in indicators
    )


# =========================================================
# SAVE AI ANALYSIS
# =========================================================

def save_ai_analysis(
    db: Session,
    result: dict,
    thread_id: str,
) -> AIAnalysis:

    existing_analysis = (
        db.query(AIAnalysis)
        .filter(
            AIAnalysis.thread_id == thread_id
        )
        .first()
    )

    if existing_analysis:
        return existing_analysis

    incident = result.get("incident") or {}
    triage = result.get("triage") or {}
    investigation = result.get("investigation") or {}
    mitre_validation = result.get("mitre_validation") or {}
    human_review = result.get("human_review") or {}
    response = result.get("response") or {}
    report = result.get("report") or {}
    rag_context = result.get("rag_context") or []
    agent_trace = result.get("agent_trace") or []

    rag_sources = [
        item.get("source")
        for item in rag_context
        if (
            isinstance(item, dict)
            and item.get("source")
        )
    ]

    risk_level = investigation.get(
        "risk_level"
    )

    if not risk_level:
        risk_level = triage.get(
            "severity",
            "unknown",
        )

    human_approval_required = human_review.get(
        "required",
        False,
    )

    human_approved = human_review.get(
        "approved"
    )

    human_review_status = human_review.get(
        "status"
    )

    human_comment = human_review.get(
        "comment"
    )

    response_status = response.get(
        "status"
    )

    if not response_status:
        response_status = report.get(
            "response_status",
            "not_executed",
        )

    db_analysis = AIAnalysis(
        incident_id=incident.get(
            "id"
        ),

        summary=investigation.get(
            "summary",
            "No summary available",
        ),

        risk_level=risk_level,

        explanation=investigation.get(
            "explanation"
        ),

        recommendation=investigation.get(
            "recommendation"
        ),

        mitre_technique=mitre_validation.get(
            "technique_id"
        ),

        mitre_name=mitre_validation.get(
            "name"
        ),

        mitre_valid=mitre_validation.get(
            "valid",
            False,
        ),

        rag_sources=rag_sources,

        human_approval_required=(
            human_approval_required
        ),

        human_approved=(
            human_approved
        ),

        human_review_status=(
            human_review_status
        ),

        human_comment=(
            human_comment
        ),

        response_status=(
            response_status
        ),

        thread_id=thread_id,

        agent_trace=agent_trace,

        model_used=settings.LLM_MODEL,
    )

    try:
        db.add(db_analysis)
        db.commit()
        db.refresh(db_analysis)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to save AI analysis: "
                f"{str(exc)}"
            ),
        )

    return db_analysis


# =========================================================
# SAVE SOC REPORT
# =========================================================

def save_soc_report(
    db: Session,
    result: dict,
    thread_id: str,
    ai_analysis_id: int,
) -> SOCReport:

    existing_report = (
        db.query(SOCReport)
        .filter(
            SOCReport.thread_id == thread_id
        )
        .first()
    )

    if existing_report:
        return existing_report

    incident = result.get("incident") or {}
    investigation = result.get("investigation") or {}
    ml_analysis = result.get("ml_analysis") or {}
    mitre_validation = result.get("mitre_validation") or {}
    human_review = result.get("human_review") or {}
    response = result.get("response") or {}
    report = result.get("report") or {}
    rag_context = result.get("rag_context") or []
    agent_trace = result.get("agent_trace") or []

    rag_sources = [
        item.get("source")
        for item in rag_context
        if (
            isinstance(item, dict)
            and item.get("source")
        )
    ]

    ml_probabilities = {
        "BENIGN": ml_analysis.get(
            "benign_probability"
        ),
        "DDoS": ml_analysis.get(
            "ddos_probability"
        ),
        "PortScan": ml_analysis.get(
            "portscan_probability"
        ),
        "FTP-Patator": ml_analysis.get(
            "ftp_patator_probability"
        ),
        "SSH-Patator": ml_analysis.get(
            "ssh_patator_probability"
        ),
    }

    db_report = SOCReport(
        incident_id=incident.get(
            "id"
        ),

        ai_analysis_id=ai_analysis_id,

        thread_id=thread_id,

        title=report.get(
            "title",
            incident.get(
                "title",
                "SOC Incident Report",
            ),
        ),

        summary=report.get(
            "summary",
            investigation.get(
                "summary",
                "No summary available",
            ),
        ),

        risk_level=report.get(
            "risk_level",
            investigation.get(
                "risk_level",
                "unknown",
            ),
        ),

        ml_status=ml_analysis.get(
            "status"
        ),

        ml_prediction=ml_analysis.get(
            "prediction"
        ),

        ml_probabilities=ml_probabilities,

        mitre_technique=report.get(
            "mitre_technique",
            mitre_validation.get(
                "technique_id"
            ),
        ),

        mitre_name=report.get(
            "mitre_name",
            mitre_validation.get(
                "name"
            ),
        ),

        recommendation=report.get(
            "recommendation",
            investigation.get(
                "recommendation"
            ),
        ),

        response_status=report.get(
            "response_status",
            response.get(
                "status",
                "not_executed",
            ),
        ),

        human_review_status=report.get(
            "human_review_status",
            human_review.get(
                "status"
            ),
        ),

        human_comment=report.get(
            "human_comment",
            human_review.get(
                "comment"
            ),
        ),

        rag_sources=rag_sources,

        agent_trace=agent_trace,
    )

    try:
        db.add(db_report)
        db.commit()
        db.refresh(db_report)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to save SOC report: "
                f"{str(exc)}"
            ),
        )

    return db_report


# =========================================================
# SAVE SOAR ACTION
# =========================================================

def save_soar_action(
    db: Session,
    result: dict,
) -> Optional[SOARAction]:

    soar_data = (
        result.get("soar_action")
        or {}
    )

    if not soar_data:
        return None

    incident_id = soar_data.get(
        "incident_id"
    )

    action_type = soar_data.get(
        "action_type"
    )

    target = soar_data.get(
        "target"
    )

    if (
        not incident_id
        or not action_type
        or not target
    ):
        return None

    human_review = (
        result.get("human_review")
        or {}
    )

    human_review_required = bool(
        human_review.get(
            "required",
            False,
        )
    )

    if human_review_required:
        approved = (
            human_review.get(
                "approved"
            )
            is True
        )
        requires_approval = True

    else:
        approved = True
        requires_approval = False

    if approved:
        action_status = "approved"
    else:
        action_status = "pending"

    existing_action = (
        db.query(SOARAction)
        .filter(
            SOARAction.incident_id
            == incident_id,

            SOARAction.action_type
            == action_type,

            SOARAction.target
            == target,
        )
        .first()
    )

    if existing_action:
        return existing_action

    db_action = SOARAction(
        incident_id=incident_id,

        action_type=action_type,

        target=target,

        status=action_status,

        requires_approval=(
            requires_approval
        ),

        approved=approved,

        result=None,

        executed_at=None,
    )

    try:
        db.add(db_action)
        db.commit()
        db.refresh(db_action)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to save SOAR action: "
                f"{str(exc)}"
            ),
        )

    return db_action


# =========================================================
# BUILD INITIAL SOC STATE
# =========================================================

def build_initial_state(
    incident: Incident,
    request: Optional[AnalyzeIncidentRequest] = None,
) -> dict:
    """
    Build the initial LangGraph state from an Incident.
    """

    return {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "source": incident.source,
            "assigned_to": incident.assigned_to,

            "hostname": incident.hostname,
            "source_ip": incident.source_ip,
            "destination_ip": (
                incident.destination_ip
            ),
            "username": incident.username,

            "ml_features": (
                request.ml_features
                if request
                else None
            ),
        }
    }


# =========================================================
# FORMAT WAITING RESPONSE
# =========================================================

def build_waiting_response(
    result: dict,
    thread_id: str,
) -> dict:

    interrupts = result.get(
        "__interrupt__",
        [],
    )

    return {
        "status": "waiting_for_human",

        "thread_id": thread_id,

        "interrupt": [
            item.value
            for item in interrupts
        ],

        "incident": result.get(
            "incident"
        ),

        "triage": result.get(
            "triage"
        ),

        "ml_analysis": result.get(
            "ml_analysis"
        ),

        "threat_intelligence": result.get(
            "threat_intelligence"
        ),

        "rag_context": result.get(
            "rag_context",
            [],
        ),

        "investigation": result.get(
            "investigation"
        ),

        "mitre_validation": result.get(
            "mitre_validation"
        ),

        "agent_trace": result.get(
            "agent_trace",
            [],
        ),
    }


# =========================================================
# FORMAT COMPLETED RESPONSE
# =========================================================

def build_completed_response(
    result: dict,
    thread_id: str,
    db_analysis: AIAnalysis,
    db_report: SOCReport,
    db_soar_action: Optional[SOARAction],
) -> dict:

    return {
        "status": "completed",

        "thread_id": thread_id,

        "ai_analysis_id": (
            db_analysis.id
        ),

        "soc_report_id": (
            db_report.id
        ),

        "soar_action_id": (
            db_soar_action.id
            if db_soar_action
            else None
        ),

        "incident": result.get(
            "incident"
        ),

        "triage": result.get(
            "triage"
        ),

        "ml_analysis": result.get(
            "ml_analysis"
        ),

        "threat_intelligence": result.get(
            "threat_intelligence"
        ),

        "rag_context": result.get(
            "rag_context",
            [],
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

        "soar_action": result.get(
            "soar_action"
        ),

        "report": result.get(
            "report"
        ),

        "agent_trace": result.get(
            "agent_trace",
            [],
        ),
    }


# =========================================================
# START SOC WORKFLOW SERVICE
# =========================================================

def run_soc_workflow(
    db: Session,
    incident: Incident,
    request: Optional[AnalyzeIncidentRequest] = None,
) -> dict:
    """
    Start the SOC LangGraph workflow.

    Workflow lifecycle:
    running -> waiting_for_human
    running -> completed
    running -> rate_limited
    running -> failed
    """

    # -----------------------------------------------------
    # 1. Mark workflow as running
    # -----------------------------------------------------

    update_incident_workflow_status(
        db=db,
        incident=incident,
        workflow_status="running",
        workflow_error=None,
    )

    # -----------------------------------------------------
    # 2. Create LangGraph thread
    # -----------------------------------------------------

    thread_id = str(
        uuid4()
    )

    config = {
        "configurable": {
            "thread_id": thread_id,
        }
    }

    # -----------------------------------------------------
    # 3. Initial state
    # -----------------------------------------------------

    initial_state = build_initial_state(
        incident=incident,
        request=request,
    )

    # -----------------------------------------------------
    # 4. Run LangGraph
    # -----------------------------------------------------

    try:
        result = soc_graph.invoke(
            initial_state,
            config=config,
        )

    except Exception as exc:

        rate_limited = is_llm_rate_limit_error(
            exc
        )

        if rate_limited:
            workflow_status = "rate_limited"
            http_status = (
                status.HTTP_429_TOO_MANY_REQUESTS
            )
            detail = (
                "SOC workflow temporarily paused because "
                "the LLM provider rate limit was reached."
            )

        else:
            workflow_status = "failed"
            http_status = (
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            detail = (
                "SOC agents workflow failed: "
                f"{str(exc)}"
            )

        try:
            update_incident_workflow_status(
                db=db,
                incident=incident,
                workflow_status=workflow_status,
                workflow_error=str(exc),
            )

        except Exception:
            pass

        raise HTTPException(
            status_code=http_status,
            detail=detail,
        )

    # -----------------------------------------------------
    # 5. Human interruption
    # -----------------------------------------------------

    interrupts = result.get(
        "__interrupt__",
        [],
    )

    if interrupts:

        update_incident_workflow_status(
            db=db,
            incident=incident,
            workflow_status="waiting_for_human",
            workflow_error=None,
        )

        return build_waiting_response(
            result=result,
            thread_id=thread_id,
        )

    # -----------------------------------------------------
    # 6. Save completed workflow
    # -----------------------------------------------------

    try:
        db_analysis = save_ai_analysis(
            db=db,
            result=result,
            thread_id=thread_id,
        )

        db_report = save_soc_report(
            db=db,
            result=result,
            thread_id=thread_id,
            ai_analysis_id=db_analysis.id,
        )

        db_soar_action = save_soar_action(
            db=db,
            result=result,
        )

    except Exception as exc:

        try:
            update_incident_workflow_status(
                db=db,
                incident=incident,
                workflow_status="failed",
                workflow_error=str(exc),
            )

        except Exception:
            pass

        raise

    # -----------------------------------------------------
    # 7. Mark workflow completed
    # -----------------------------------------------------

    update_incident_workflow_status(
        db=db,
        incident=incident,
        workflow_status="completed",
        workflow_error=None,
    )

    return build_completed_response(
        result=result,
        thread_id=thread_id,
        db_analysis=db_analysis,
        db_report=db_report,
        db_soar_action=db_soar_action,
    )


# =========================================================
# START SOC WORKFLOW ENDPOINT
# =========================================================

@router.post("/analyze/{incident_id}")
def analyze_incident_with_agents(
    incident_id: int,
    request: Optional[AnalyzeIncidentRequest] = None,
    db: Session = Depends(get_db),
):

    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Incident not found",
        )

    return run_soc_workflow(
        db=db,
        incident=incident,
        request=request,
    )


# =========================================================
# RESUME SOC WORKFLOW
# =========================================================

@router.post("/resume/{thread_id}")
def resume_soc_workflow(
    thread_id: str,
    decision: HumanDecision,
    db: Session = Depends(get_db),
):

    config = {
        "configurable": {
            "thread_id": thread_id,
        }
    }

    # -----------------------------------------------------
    # 1. Read checkpoint
    # -----------------------------------------------------

    try:
        snapshot = soc_graph.get_state(
            config
        )

    except Exception as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to read workflow state: "
                f"{str(exc)}"
            ),
        )

    # -----------------------------------------------------
    # 2. Check workflow exists
    # -----------------------------------------------------

    if not snapshot.values:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Workflow not found. "
                "The checkpoint may have been lost. "
                "Run /agents/analyze/{incident_id} again."
            ),
        )

    # -----------------------------------------------------
    # 3. Check incident
    # -----------------------------------------------------

    incident_state = snapshot.values.get(
        "incident"
    )

    if not incident_state:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "Workflow state is incomplete: "
                "incident data is missing."
            ),
        )

    incident_id = incident_state.get(
        "id"
    )

    if not incident_id:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "Workflow state is incomplete: "
                "incident id is missing."
            ),
        )

    db_incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )

    if not db_incident:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Incident not found in database."
            ),
        )

    # -----------------------------------------------------
    # 4. Check investigation
    # -----------------------------------------------------

    investigation_state = snapshot.values.get(
        "investigation"
    )

    if not investigation_state:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "Workflow state is incomplete: "
                "investigation data is missing."
            ),
        )

    # -----------------------------------------------------
    # 5. Check waiting state
    # -----------------------------------------------------

    if not snapshot.next:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "This workflow is not waiting "
                "for human approval."
            ),
        )

    # -----------------------------------------------------
    # 6. Mark workflow as running again
    # -----------------------------------------------------

    update_incident_workflow_status(
        db=db,
        incident=db_incident,
        workflow_status="running",
        workflow_error=None,
    )

    # -----------------------------------------------------
    # 7. Resume LangGraph
    # -----------------------------------------------------

    try:
        result = soc_graph.invoke(
            Command(
                resume={
                    "approved": (
                        decision.approved
                    ),
                    "comment": (
                        decision.comment
                    ),
                }
            ),
            config=config,
        )

    except Exception as exc:

        rate_limited = is_llm_rate_limit_error(
            exc
        )

        if rate_limited:
            workflow_status = "rate_limited"
            http_status = (
                status.HTTP_429_TOO_MANY_REQUESTS
            )
            detail = (
                "SOC workflow temporarily paused because "
                "the LLM provider rate limit was reached."
            )

        else:
            workflow_status = "failed"
            http_status = (
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            detail = (
                "Unable to resume workflow: "
                f"{str(exc)}"
            )

        try:
            update_incident_workflow_status(
                db=db,
                incident=db_incident,
                workflow_status=workflow_status,
                workflow_error=str(exc),
            )

        except Exception:
            pass

        raise HTTPException(
            status_code=http_status,
            detail=detail,
        )

    # -----------------------------------------------------
    # 8. Check another interruption
    # -----------------------------------------------------

    remaining_interrupts = result.get(
        "__interrupt__",
        [],
    )

    if remaining_interrupts:

        update_incident_workflow_status(
            db=db,
            incident=db_incident,
            workflow_status="waiting_for_human",
            workflow_error=None,
        )

        return build_waiting_response(
            result=result,
            thread_id=thread_id,
        )

    # -----------------------------------------------------
    # 9. Save final workflow results
    # -----------------------------------------------------

    try:
        db_analysis = save_ai_analysis(
            db=db,
            result=result,
            thread_id=thread_id,
        )

        db_report = save_soc_report(
            db=db,
            result=result,
            thread_id=thread_id,
            ai_analysis_id=db_analysis.id,
        )

        db_soar_action = save_soar_action(
            db=db,
            result=result,
        )

    except Exception as exc:

        try:
            update_incident_workflow_status(
                db=db,
                incident=db_incident,
                workflow_status="failed",
                workflow_error=str(exc),
            )

        except Exception:
            pass

        raise

    # -----------------------------------------------------
    # 10. Mark completed
    # -----------------------------------------------------

    update_incident_workflow_status(
        db=db,
        incident=db_incident,
        workflow_status="completed",
        workflow_error=None,
    )

    # -----------------------------------------------------
    # 11. Final response
    # -----------------------------------------------------

    return build_completed_response(
        result=result,
        thread_id=thread_id,
        db_analysis=db_analysis,
        db_report=db_report,
        db_soar_action=db_soar_action,
    )