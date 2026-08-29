import operator

from typing import TypedDict, Literal, Annotated

from psycopg import Connection
from psycopg.rows import dict_row

from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.graph import StateGraph, START, END
from langgraph.types import interrupt

from app.core.config import settings

from app.services.llm_service import LLMService
from app.services.mitre_service import MitreService
from app.services.rag_service import RAGService
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

    rag_context: list[dict]

    investigation: dict

    mitre_validation: dict

    human_review: dict

    response: dict

    soar_action: dict

    report: dict

    agent_trace: Annotated[
        list[str],
        operator.add,
    ]


# =========================================================
# 1. TRIAGE AGENT
# =========================================================

def triage_agent(
    state: SOCState,
) -> dict:

    incident = state.get(
        "incident",
        {},
    )

    severity = str(
        incident.get(
            "severity",
            "medium",
        )
    ).lower().strip()

    triage = {
        "status": "triaged",
        "severity": severity,
        "priority": severity.upper(),
    }

    return {
        "triage": triage,

        "agent_trace": [
            "Triage"
        ],
    }


# =========================================================
# 2. THREAT INTELLIGENCE AGENT
# =========================================================

def threat_intelligence_agent(
    state: SOCState,
) -> dict:

    incident = state.get(
        "incident",
        {},
    )

    service = (
        ThreatIntelligenceService()
    )

    text = (
        f"{incident.get('title', '')} "
        f"{incident.get('description', '')}"
    )

    try:

        result = service.analyze_text(
            text
        )

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
        "threat_intelligence": result,

        "agent_trace": [
            "Threat Intelligence"
        ],
    }


# =========================================================
# 3. INVESTIGATION AGENT
# =========================================================

def investigation_agent(
    state: SOCState,
) -> dict:

    incident = state.get(
        "incident",
        {},
    )

    threat_intelligence = state.get(
        "threat_intelligence",
        [],
    )

    # -----------------------------------------------------
    # RAG SEARCH
    # -----------------------------------------------------

    rag_service = RAGService()

    rag_query = (
        f"{incident.get('title', '')} "
        f"{incident.get('description', '')} "
        f"{incident.get('severity', '')}"
    )

    try:

        rag_context = rag_service.search(
            rag_query,
            limit=3,
        )

    except Exception as exc:

        print(
            f"RAG search failed: {str(exc)}"
        )

        rag_context = []

    # -----------------------------------------------------
    # LLM ANALYSIS
    # -----------------------------------------------------

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

        threat_intelligence=(
            threat_intelligence
        ),

        rag_context=rag_context,
    )

    # -----------------------------------------------------
    # MITRE ATT&CK VALIDATION
    # -----------------------------------------------------

    mitre_service = (
        MitreService()
    )

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
                mitre_service
                .validate_technique(
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

        "rag_context": rag_context,

        "mitre_validation": (
            mitre_validation
        ),

        "agent_trace": [
            "Investigation"
        ],
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

    if (
        incident_severity
        in high_risk_levels
        or ai_risk_level
        in high_risk_levels
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

    decision = interrupt(
        {
            "message": (
                "This incident requires "
                "SOC analyst approval."
            ),

            "incident_id": (
                incident.get("id")
            ),

            "title": (
                incident.get("title")
            ),

            "risk_level": (
                investigation.get(
                    "risk_level"
                )
            ),

            "recommendation": (
                investigation.get(
                    "recommendation"
                )
            ),

            "question": (
                "Approve the recommended "
                "response?"
            ),
        }
    )

    if isinstance(
        decision,
        dict,
    ):

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
        "human_review": (
            human_review
        ),

        "agent_trace": [
            "Human Review"
        ],
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

    return "report"


# =========================================================
# SOAR ACTION BUILDER
# =========================================================

def build_soar_action(
    incident: dict,
    recommendation: str,
) -> dict:

    recommendation_lower = str(
        recommendation or ""
    ).lower()

    # -----------------------------------------------------
    # 1. Déterminer le type d'action SOAR
    # -----------------------------------------------------

    action_type = "create_ticket"

    if "isolate" in recommendation_lower:

        action_type = "isolate_endpoint"

    elif (
        "block" in recommendation_lower
        and "ip" in recommendation_lower
    ):

        action_type = "block_ip"

    elif (
        "disable" in recommendation_lower
        and (
            "user" in recommendation_lower
            or "account" in recommendation_lower
        )
    ):

        action_type = "disable_user"

    elif (
        "notify" in recommendation_lower
        or "notification" in recommendation_lower
    ):

        action_type = "send_notification"

    # -----------------------------------------------------
    # 2. Déterminer la cible selon le type d'action
    # -----------------------------------------------------

    if action_type == "isolate_endpoint":

        target = (
            incident.get("hostname")
            or incident.get("endpoint")
            or incident.get("device_name")
            or incident.get("target")
            or "unknown-endpoint"
        )

    elif action_type == "block_ip":

        target = (
            incident.get("ip_address")
            or incident.get("source_ip")
            or incident.get("src_ip")
            or incident.get("ip")
            or incident.get("target")
            or "unknown-ip"
        )

    elif action_type == "disable_user":

        target = (
            incident.get("username")
            or incident.get("user")
            or incident.get("account")
            or incident.get("target")
            or "unknown-user"
        )

    elif action_type == "send_notification":

        target = (
            incident.get("notification_target")
            or "soc-team"
        )

    else:

        target = (
            incident.get("hostname")
            or incident.get("endpoint")
            or incident.get("target")
            or f"incident-{incident.get('id', 'unknown')}"
        )

    # -----------------------------------------------------
    # 3. Construire la proposition SOAR
    # -----------------------------------------------------

    return {
        "incident_id": (
            incident.get("id")
        ),

        "action_type": (
            action_type
        ),

        "target": (
            target
        ),

        "requires_approval": True,

        "status": "proposed",
    }


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

        "automatic_execution": False,

        "human_approval_required": (
            high_risk
        ),

        "human_approved": (
            approved
        ),

        "status": (
            "approved_for_response"
            if approved
            else "blocked"
        ),
    }

    # -----------------------------------------------------
    # Construire SOAR action seulement si autorisée
    # -----------------------------------------------------

    soar_action = {}

    if approved:

        soar_action = build_soar_action(
            incident=incident,

            recommendation=(
                investigation.get(
                    "recommendation",
                    "",
                )
            ),
        )

    return {
        "response": response,

        "soar_action": soar_action,

        "agent_trace": [
            "Response"
        ],
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

    mitre_validation = state.get(
        "mitre_validation",
        {},
    )

    human_review = state.get(
        "human_review",
        {},
    )

    response = state.get(
        "response",
        {},
    )

    soar_action = state.get(
        "soar_action",
        {},
    )

    # -----------------------------------------------------
    # RAG SOURCES
    # -----------------------------------------------------

    rag_context = state.get(
        "rag_context",
        [],
    )

    rag_sources = [
        item.get("source")
        for item in rag_context
        if (
            isinstance(item, dict)
            and item.get("source")
        )
    ]

    # -----------------------------------------------------
    # REPORT
    # -----------------------------------------------------

    report = {
        "incident_id": (
            incident.get(
                "id"
            )
        ),

        "title": (
            incident.get(
                "title"
            )
        ),

        "summary": (
            investigation.get(
                "summary"
            )
        ),

        "risk_level": (
            investigation.get(
                "risk_level"
            )
        ),

        "mitre_technique": (
            mitre_validation.get(
                "technique_id"
            )
        ),

        "mitre_name": (
            mitre_validation.get(
                "name"
            )
        ),

        "mitre_valid": (
            mitre_validation.get(
                "valid"
            )
        ),

        "recommendation": (
            investigation.get(
                "recommendation"
            )
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

        "soar_action": (
            soar_action
        ),

        "rag_sources": (
            rag_sources
        ),
    }

    return {
        "report": report,

        "agent_trace": [
            "Report"
        ],
    }


# =========================================================
# LANGGRAPH BUILDER
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
        "human_review": (
            "human_review"
        ),

        "response": (
            "response"
        ),
    },
)


# =========================================================
# HUMAN DECISION
# =========================================================

builder.add_conditional_edges(
    "human_review",
    approval_router,
    {
        "response": (
            "response"
        ),

        "report": (
            "report"
        ),
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
# POSTGRESQL CHECKPOINTER
# =========================================================

checkpoint_connection = (
    Connection.connect(
        settings.DATABASE_URL,
        autocommit=True,
        prepare_threshold=0,
        row_factory=dict_row,
    )
)


checkpointer = PostgresSaver(
    checkpoint_connection
)


# Crée les tables LangGraph si nécessaire.
checkpointer.setup()


# =========================================================
# COMPILE GRAPH
# =========================================================

soc_graph = builder.compile(
    checkpointer=checkpointer
)