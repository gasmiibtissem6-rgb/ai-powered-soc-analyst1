import operator

from typing import Annotated, Literal, TypedDict

from psycopg import Connection
from psycopg.rows import dict_row

from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from app.core.config import settings

from app.services.llm_service import LLMService
from app.services.mitre_service import MitreService
from app.services.ml_service import MLService
from app.services.rag_service import RAGService
from app.services.soar_service import SOARService
from app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
)


# =========================================================
# STATE
# =========================================================

class SOCState(TypedDict, total=False):

    incident: dict

    correlated_incidents: list[dict]

    triage: dict

    ml_analysis: dict

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
# 2. MACHINE LEARNING AGENT
# =========================================================

def machine_learning_agent(
    state: SOCState,
) -> dict:

    incident = state.get(
        "incident",
        {},
    )

    features = incident.get(
        "ml_features"
    )

    # -----------------------------------------------------
    # No ML feature vector provided
    # -----------------------------------------------------

    if (
        not isinstance(
            features,
            dict,
        )
        or not features
    ):

        return {
            "ml_analysis": {
                "status": "not_available",
                "prediction": None,
                "reason": (
                    "No network ML features "
                    "provided for this incident."
                ),
            },

            "agent_trace": [
                "Machine Learning"
            ],
        }

    # -----------------------------------------------------
    # Random Forest prediction
    # -----------------------------------------------------

    try:

        service = MLService()

        prediction = (
            service.predict_network_attack(
                features
            )
        )

        ml_analysis = {
            "status": "success",
            **prediction,
        }

    except Exception as exc:

        ml_analysis = {
            "status": "failed",
            "prediction": None,
            "error": str(exc),
        }

    return {
        "ml_analysis": ml_analysis,

        "agent_trace": [
            "Machine Learning"
        ],
    }


# =========================================================
# 3. THREAT INTELLIGENCE AGENT
# =========================================================

def threat_intelligence_agent(
    state: SOCState,
) -> dict:
    """
    Enrich the primary incident and correlated incidents
    with Threat Intelligence.

    All unique IP addresses are collected first so the same
    IP is never queried multiple times.
    """

    incident = state.get(
        "incident",
        {},
    )

    correlated_incidents = state.get(
        "correlated_incidents",
        [],
    )

    service = ThreatIntelligenceService()

    results = []

    # IPs already processed by Threat Intelligence
    analyzed_ips = set()

    # IPs discovered across all incident sources
    candidate_ips = set()

    # =====================================================
    # 1. PRIMARY INCIDENT
    # =====================================================

    primary_source_ip = incident.get(
        "source_ip"
    )

    primary_destination_ip = incident.get(
        "destination_ip"
    )

    if primary_source_ip:
        candidate_ips.add(
            primary_source_ip
        )

    if primary_destination_ip:
        candidate_ips.add(
            primary_destination_ip
        )

    primary_text = (
        f"{incident.get('title', '')} "
        f"{incident.get('description', '')}"
    )

    try:
        extracted_primary_ips = (
            service.extract_ips(
                primary_text
            )
        )

        for ip_address in extracted_primary_ips:

            if ip_address:
                candidate_ips.add(
                    ip_address
                )

    except Exception as exc:

        print(
            "Threat Intelligence IP extraction "
            f"failed for primary incident: {str(exc)}"
        )

    # =====================================================
    # 2. CORRELATED INCIDENTS
    # =====================================================

    for correlated in correlated_incidents:

        if not isinstance(
            correlated,
            dict,
        ):
            continue

        correlated_source_ip = (
            correlated.get(
                "source_ip"
            )
        )

        correlated_destination_ip = (
            correlated.get(
                "destination_ip"
            )
        )

        if correlated_source_ip:
            candidate_ips.add(
                correlated_source_ip
            )

        if correlated_destination_ip:
            candidate_ips.add(
                correlated_destination_ip
            )

        correlated_text = (
            f"{correlated.get('title', '')} "
            f"{correlated.get('description', '')}"
        )

        try:

            extracted_correlated_ips = (
                service.extract_ips(
                    correlated_text
                )
            )

            for ip_address in (
                extracted_correlated_ips
            ):

                if ip_address:
                    candidate_ips.add(
                        ip_address
                    )

        except Exception as exc:

            print(
                "Threat Intelligence IP extraction "
                "failed for correlated incident "
                f"{correlated.get('id')}: "
                f"{str(exc)}"
            )

    # =====================================================
    # 3. THREAT INTELLIGENCE LOOKUPS
    # =====================================================

    for ip_address in sorted(
        candidate_ips
    ):

        if not ip_address:
            continue

        if ip_address in analyzed_ips:
            continue

        try:

            result = service.check_ip(
                ip_address
            )

            # Add useful provenance information
            if isinstance(
                result,
                dict,
            ):

                result["observed_in"] = []

                if (
                    ip_address
                    == incident.get(
                        "source_ip"
                    )
                    or ip_address
                    == incident.get(
                        "destination_ip"
                    )
                    or ip_address
                    in primary_text
                ):

                    result[
                        "observed_in"
                    ].append(
                        {
                            "incident_id": (
                                incident.get(
                                    "id"
                                )
                            ),
                            "source": (
                                incident.get(
                                    "source"
                                )
                            ),
                            "role": "primary",
                        }
                    )

                for correlated in (
                    correlated_incidents
                ):

                    if not isinstance(
                        correlated,
                        dict,
                    ):
                        continue

                    correlated_text = (
                        f"{correlated.get('title', '')} "
                        f"{correlated.get('description', '')}"
                    )

                    if (
                        ip_address
                        == correlated.get(
                            "source_ip"
                        )
                        or ip_address
                        == correlated.get(
                            "destination_ip"
                        )
                        or ip_address
                        in correlated_text
                    ):

                        result[
                            "observed_in"
                        ].append(
                            {
                                "incident_id": (
                                    correlated.get(
                                        "id"
                                    )
                                ),
                                "source": (
                                    correlated.get(
                                        "source"
                                    )
                                ),
                                "role": "correlated",
                            }
                        )

            results.append(
                result
            )

        except Exception as exc:

            results.append(
                {
                    "ip_address": ip_address,

                    "error": (
                        "Threat Intelligence failed: "
                        f"{str(exc)}"
                    ),
                }
            )

        finally:

            analyzed_ips.add(
                ip_address
            )

    # =====================================================
    # 4. RESULT
    # =====================================================

    return {
        "threat_intelligence": (
            results
        ),

        "agent_trace": [
            "Threat Intelligence"
        ],
    }


# =========================================================
# 4. INVESTIGATION AGENT
# =========================================================

def investigation_agent(
    state: SOCState,
) -> dict:

    incident = state.get(
        "incident",
        {},
    )

    correlated_incidents = state.get(
        "correlated_incidents",
        [],
    )

    threat_intelligence = state.get(
        "threat_intelligence",
        [],
    )

    ml_analysis = state.get(
        "ml_analysis",
        {},
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
    # Add ML result to investigation context
    # -----------------------------------------------------

    ml_context = []

    if (
        isinstance(
            ml_analysis,
            dict,
        )
        and ml_analysis.get(
            "status"
        ) == "success"
    ):

        ml_context = [
            {
                "source": "machine_learning",

                "prediction": (
                    ml_analysis.get(
                        "prediction"
                    )
                ),

                "benign_probability": (
                    ml_analysis.get(
                        "benign_probability"
                    )
                ),

                "ddos_probability": (
                    ml_analysis.get(
                        "ddos_probability"
                    )
                ),

                "portscan_probability": (
                    ml_analysis.get(
                        "portscan_probability"
                    )
                ),

                "ftp_patator_probability": (
                    ml_analysis.get(
                        "ftp_patator_probability"
                    )
                ),

                "ssh_patator_probability": (
                    ml_analysis.get(
                        "ssh_patator_probability"
                    )
                ),
            }
        ]

    # -----------------------------------------------------
    # Add correlated multi-source evidence
    # -----------------------------------------------------

    correlation_context = []

    for correlated in correlated_incidents:

        if not isinstance(
            correlated,
            dict,
        ):
            continue

        correlation_context.append(
            {
                "source": "correlated_incident",

                "incident_id": (
                    correlated.get(
                        "id"
                    )
                ),

                "sensor_source": (
                    correlated.get(
                        "source"
                    )
                ),

                "title": (
                    correlated.get(
                        "title"
                    )
                ),

                "description": (
                    correlated.get(
                        "description"
                    )
                ),

                "severity": (
                    correlated.get(
                        "severity"
                    )
                ),

                "status": (
                    correlated.get(
                        "status"
                    )
                ),

                "hostname": (
                    correlated.get(
                        "hostname"
                    )
                ),

                "source_ip": (
                    correlated.get(
                        "source_ip"
                    )
                ),

                "destination_ip": (
                    correlated.get(
                        "destination_ip"
                    )
                ),

                "username": (
                    correlated.get(
                        "username"
                    )
                ),

                "workflow_status": (
                    correlated.get(
                        "workflow_status"
                    )
                ),

                "correlation_id": (
                    correlated.get(
                        "correlation_id"
                    )
                ),

                "created_at": (
                    correlated.get(
                        "created_at"
                    )
                ),
            }
        )

    # -----------------------------------------------------
    # Final investigation context
    # -----------------------------------------------------

    investigation_context = (
        rag_context
        + ml_context
        + correlation_context
    )

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

        rag_context=(
            investigation_context
        ),
    )

    # -----------------------------------------------------
    # Add ML result to investigation result
    # -----------------------------------------------------

    result["ml_analysis"] = (
        ml_analysis
    )

    # -----------------------------------------------------
    # Add correlation information to investigation result
    # -----------------------------------------------------

    result["correlation_id"] = (
        incident.get(
            "correlation_id"
        )
    )

    result["correlated_incident_count"] = (
        len(
            correlated_incidents
        )
    )

    result["correlated_sources"] = sorted(
        {
            str(
                item.get(
                    "source"
                )
            )
            for item in correlated_incidents
            if (
                isinstance(
                    item,
                    dict,
                )
                and item.get(
                    "source"
                )
            )
        }
    )

    # -----------------------------------------------------
    # MITRE ATT&CK VALIDATION
    # -----------------------------------------------------

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

        # Important:
        # Preserve RAG + ML + correlated evidence.
        "rag_context": (
            investigation_context
        ),

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
# 5. HUMAN REVIEW AGENT
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
    """
    Build a safe SOAR action from the AI recommendation.

    Safety rules:
    - Invalid endpoint isolation -> create_ticket
    - Invalid/protected IP blocking -> create_ticket
    - Missing user for disable_user -> create_ticket
    """

    recommendation_lower = str(
        recommendation or ""
    ).lower()

    action_type = "create_ticket"

    # =====================================================
    # DETERMINE ACTION TYPE
    # =====================================================

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

    # =====================================================
    # ISOLATE ENDPOINT
    # =====================================================

    if action_type == "isolate_endpoint":

        target = (
            incident.get("hostname")
            or incident.get("endpoint")
            or incident.get("device_name")
            or incident.get("target")
        )

        if not SOARService.is_safe_endpoint_target(
            target
        ):

            action_type = "create_ticket"

            target = (
                incident.get("hostname")
                or (
                    f"incident-"
                    f"{incident.get('id', 'unknown')}"
                )
            )

    # =====================================================
    # BLOCK IP
    # =====================================================

    elif action_type == "block_ip":

        target = (
            incident.get("ip_address")
            or incident.get("source_ip")
            or incident.get("src_ip")
            or incident.get("ip")
            or incident.get("target")
        )

        if not SOARService.is_safe_ip_target(
            target
        ):

            action_type = "create_ticket"

            target = (
                incident.get("hostname")
                or (
                    f"incident-"
                    f"{incident.get('id', 'unknown')}"
                )
            )

    # =====================================================
    # DISABLE USER
    # =====================================================

    elif action_type == "disable_user":

        target = (
            incident.get("username")
            or incident.get("user")
            or incident.get("account")
            or incident.get("target")
        )

        if not target:

            action_type = "create_ticket"

            target = (
                incident.get("hostname")
                or (
                    f"incident-"
                    f"{incident.get('id', 'unknown')}"
                )
            )

    # =====================================================
    # SEND NOTIFICATION
    # =====================================================

    elif action_type == "send_notification":

        target = (
            incident.get(
                "notification_target"
            )
            or "soc-team"
        )

    # =====================================================
    # CREATE TICKET / DEFAULT
    # =====================================================

    else:

        target = (
            incident.get("hostname")
            or incident.get("endpoint")
            or incident.get("target")
            or (
                f"incident-"
                f"{incident.get('id', 'unknown')}"
            )
        )

    # =====================================================
    # FINAL SAFETY FALLBACK
    # =====================================================

    if not target:

        action_type = "create_ticket"

        target = (
            f"incident-"
            f"{incident.get('id', 'unknown')}"
        )

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
# 6. RESPONSE AGENT
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
# 7. REPORT AGENT
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

    ml_analysis = state.get(
        "ml_analysis",
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

        "ml_status": (
            ml_analysis.get(
                "status"
            )
        ),

        "ml_prediction": (
            ml_analysis.get(
                "prediction"
            )
        ),

        "ml_probabilities": {
            "BENIGN": (
                ml_analysis.get(
                    "benign_probability"
                )
            ),

            "DDoS": (
                ml_analysis.get(
                    "ddos_probability"
                )
            ),

            "PortScan": (
                ml_analysis.get(
                    "portscan_probability"
                )
            ),

            "FTP-Patator": (
                ml_analysis.get(
                    "ftp_patator_probability"
                )
            ),

            "SSH-Patator": (
                ml_analysis.get(
                    "ssh_patator_probability"
                )
            ),
        },

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

        "correlation_id": (
            investigation.get(
                "correlation_id"
            )
        ),

        "correlated_incident_count": (
            investigation.get(
                "correlated_incident_count",
                0,
            )
        ),

        "correlated_sources": (
            investigation.get(
                "correlated_sources",
                [],
            )
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
    "machine_learning",
    machine_learning_agent,
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
    "machine_learning",
)

builder.add_edge(
    "machine_learning",
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


# Create LangGraph tables when necessary
checkpointer.setup()


# =========================================================
# COMPILE GRAPH
# =========================================================

soc_graph = builder.compile(
    checkpointer=checkpointer
)