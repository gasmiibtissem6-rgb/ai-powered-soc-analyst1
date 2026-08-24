from typing import TypedDict, Literal

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import StateGraph, START, END
from langgraph.types import interrupt

from app.services.llm_service import LLMService
from app.services.mitre_service import MitreService
from app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
)


# =========================================================
# STATE
# =========================================================

class SOCState(TypedDict, total=False):
    incident: dict
    triage: dict
    threat_intelligence: list[dict]
    investigation: dict
    mitre_validation: dict
    human_review: dict
    response: dict
    report: dict


# =========================================================
# 1. TRIAGE AGENT
# =========================================================

def triage_agent(state: SOCState) -> dict:

    incident = state.get("incident", {})

    severity = str(
        incident.get("severity", "medium")
    ).lower().strip()

    return {
        "triage": {
            "status": "triaged",
            "severity": severity,
            "priority": severity.upper(),
        }
    }


# =========================================================
# 2. THREAT INTELLIGENCE AGENT
# =========================================================

def threat_intelligence_agent(
    state: SOCState,
) -> dict:

    incident = state.get("incident", {})

    service = ThreatIntelligenceService()

    text = (
        f"{incident.get('title', '')} "
        f"{incident.get('description', '')}"
    )

    try:
        result = service.analyze_text(text)

    except Exception as exc:
        result = [
            {
                "error": (
                    "Threat Intelligence failed: "
                    f"{str(exc)}"
                )
            }
        ]

    return {
        "threat_intelligence": result
    }


# =========================================================
# 3. INVESTIGATION AGENT
# =========================================================

def investigation_agent(
    state: SOCState,
) -> dict:

    incident = state.get("incident", {})

    llm = LLMService()

    result = llm.analyze_incident(
        title=incident.get(
            "title",
            "",
        ),
        description=incident.get(
            "description",
            "",
        ),
        severity=incident.get(
            "severity",
            "medium",
        ),
        source=incident.get(
            "source",
            "unknown",
        ),
        threat_intelligence=state.get(
            "threat_intelligence",
            [],
        ),
    )

    # =========================================
    # MITRE ATT&CK validation
    # =========================================

    mitre_service = MitreService()

    mitre_value = result.get(
        "mitre_technique",
        "",
    )

    mitre_id = (
        str(mitre_value)
        .split(" ")[0]
        .strip()
    )

    if mitre_id:

        try:
            mitre_validation = (
                mitre_service.validate_technique(
                    mitre_id
                )
            )

        except Exception as exc:
            mitre_validation = {
                "technique_id": mitre_id,
                "name": None,
                "description": None,
                "valid": False,
                "error": str(exc),
            }

    else:

        mitre_validation = {
            "technique_id": None,
            "name": None,
            "description": None,
            "valid": False,
        }

    return {
        "investigation": result,
        "mitre_validation": mitre_validation,
    }


# =========================================================
# RISK ROUTER
# =========================================================

def risk_router(
    state: SOCState,
) -> Literal[
    "human_review",
    "response",
]:

    incident = state.get(
        "incident",
        {},
    )

    investigation = state.get(
        "investigation",
        {},
    )

    incident_severity = str(
        incident.get(
            "severity",
            "medium",
        )
    ).lower().strip()

    ai_risk_level = str(
        investigation.get(
            "risk_level",
            "medium",
        )
    ).lower().strip()

    high_risk_levels = {
        "high",
        "critical",
    }

    # Si incident OU IA = HIGH / CRITICAL
    # => validation humaine
    if (
        incident_severity in high_risk_levels
        or ai_risk_level in high_risk_levels
    ):
        return "human_review"

    return "response"


# =========================================================
# 4. HUMAN REVIEW AGENT
# =========================================================

def human_review_agent(
    state: SOCState,
) -> dict:

    incident = state.get(
        "incident",
        {},
    )

    investigation = state.get(
        "investigation",
        {},
    )

    # =========================================
    # LE GRAPH SE MET EN PAUSE ICI
    # =========================================

    decision = interrupt(
        {
            "message": (
                "This incident requires "
                "SOC analyst approval."
            ),

            "incident_id": incident.get(
                "id"
            ),

            "title": incident.get(
                "title"
            ),

            "risk_level": investigation.get(
                "risk_level"
            ),

            "recommendation": investigation.get(
                "recommendation"
            ),

            "question": (
                "Approve the recommended response?"
            ),
        }
    )

    # =========================================
    # APRÈS Command(resume=...)
    # =========================================

    if isinstance(decision, dict):

        approved = bool(
            decision.get(
                "approved",
                False,
            )
        )

        comment = decision.get(
            "comment"
        )

    else:

        approved = bool(
            decision
        )

        comment = None

    human_review = {
        "required": True,

        "approved": approved,

        "status": (
            "approved"
            if approved
            else "rejected"
        ),

        "comment": comment,
    }

    return {
        "human_review": human_review
    }


# =========================================================
# APPROVAL ROUTER
# =========================================================

def approval_router(
    state: SOCState,
) -> Literal[
    "response",
    "report",
]:

    review = state.get(
        "human_review",
        {},
    )

    if review.get(
        "approved"
    ) is True:

        return "response"

    # Rejected
    return "report"


# =========================================================
# 5. RESPONSE AGENT
# =========================================================

def response_agent(
    state: SOCState,
) -> dict:

    investigation = state.get(
        "investigation",
        {},
    )

    human_review = state.get(
        "human_review",
        {},
    )

    incident = state.get(
        "incident",
        {},
    )

    ai_risk = str(
        investigation.get(
            "risk_level",
            "medium",
        )
    ).lower().strip()

    incident_severity = str(
        incident.get(
            "severity",
            "medium",
        )
    ).lower().strip()

    high_risk = (
        ai_risk in {
            "high",
            "critical",
        }
        or incident_severity in {
            "high",
            "critical",
        }
    )

    if high_risk:

        approved = (
            human_review.get(
                "approved"
            )
            is True
        )

    else:

        approved = True

    response = {
        "recommended_action": (
            investigation.get(
                "recommendation"
            )
        ),

        "risk_level": ai_risk,

        # Pas encore d'action SOAR réelle.
        "automatic_execution": False,

        "human_approval_required": high_risk,

        "human_approved": approved,

        "status": (
            "approved_for_response"
            if approved
            else "blocked"
        ),
    }

    return {
        "response": response
    }


# =========================================================
# 6. REPORT AGENT
# =========================================================

def report_agent(
    state: SOCState,
) -> dict:

    incident = state.get(
        "incident",
        {},
    )

    investigation = state.get(
        "investigation",
        {},
    )

    mitre = state.get(
        "mitre_validation",
        {},
    )

    response = state.get(
        "response",
        {},
    )

    human_review = state.get(
        "human_review",
        {},
    )

    report = {
        "incident_id": incident.get(
            "id"
        ),

        "title": incident.get(
            "title"
        ),

        "summary": investigation.get(
            "summary"
        ),

        "risk_level": investigation.get(
            "risk_level"
        ),

        "mitre_technique": mitre.get(
            "technique_id"
        ),

        "mitre_name": mitre.get(
            "name"
        ),

        "mitre_valid": mitre.get(
            "valid"
        ),

        "recommendation": investigation.get(
            "recommendation"
        ),

        "human_approval_required": (
            human_review.get(
                "required",
                False,
            )
        ),

        "human_review_status": (
            human_review.get(
                "status",
                "not_required",
            )
        ),

        "human_comment": (
            human_review.get(
                "comment"
            )
        ),

        "response_status": (
            response.get(
                "status",
                "not_executed",
            )
        ),
    }

    return {
        "report": report
    }


# =========================================================
# CONSTRUCTION LANGGRAPH
# =========================================================

builder = StateGraph(
    SOCState
)


# =========================================================
# NODES
# =========================================================

builder.add_node(
    "triage",
    triage_agent,
)

builder.add_node(
    "threat_intelligence",
    threat_intelligence_agent,
)

builder.add_node(
    "investigation",
    investigation_agent,
)

builder.add_node(
    "human_review",
    human_review_agent,
)

builder.add_node(
    "response",
    response_agent,
)

builder.add_node(
    "report",
    report_agent,
)


# =========================================================
# NORMAL FLOW
# =========================================================

builder.add_edge(
    START,
    "triage",
)

builder.add_edge(
    "triage",
    "threat_intelligence",
)

builder.add_edge(
    "threat_intelligence",
    "investigation",
)


# =========================================================
# RISK DECISION
# =========================================================

builder.add_conditional_edges(
    "investigation",
    risk_router,
    {
        "human_review": "human_review",
        "response": "response",
    },
)


# =========================================================
# HUMAN DECISION
# =========================================================

builder.add_conditional_edges(
    "human_review",
    approval_router,
    {
        "response": "response",
        "report": "report",
    },
)


# =========================================================
# FINAL FLOW
# =========================================================

builder.add_edge(
    "response",
    "report",
)

builder.add_edge(
    "report",
    END,
)


# =========================================================
# CHECKPOINTER
# =========================================================

checkpointer = InMemorySaver()


# =========================================================
# COMPILE
# =========================================================

soc_graph = builder.compile(
    checkpointer=checkpointer
)