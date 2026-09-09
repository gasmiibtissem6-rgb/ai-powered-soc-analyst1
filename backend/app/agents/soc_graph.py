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
from app.services.correlation_service import CorrelationService
from app.services.ioc_extractor import IOCExtractor
import ipaddress
from app.services.threat_intelligence_enrichment_service import (
    ThreatIntelligenceEnrichmentService,
)
from app.services.ioc_extractor import IOCExtractor
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

    attack_type = (
        CorrelationService.classify_attack_type(
            incident.get("title"),
            incident.get("description"),
        )
    )

    triage = {
        "status": "triaged",
        "severity": severity,
        "priority": severity.upper(),
        "attack_type": attack_type,
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

    ml_features = incident.get(
        "ml_features"
    )

    suricata_event = incident.get(
        "suricata_event"
    )

    service = MLService()

    rf_result = None
    xgb_result = None
    isolation_result = None

    errors = {}

    # =====================================================
    # 1. Random Forest - CICIDS2017 classification
    # =====================================================

    if (
        isinstance(
            ml_features,
            dict,
        )
        and ml_features
    ):
        try:
            rf_result = (
                service.predict_network_attack(
                    ml_features
                )
            )

        except Exception as exc:
            errors["random_forest"] = str(
                exc
            )

    # =====================================================
    # 2. XGBoost - CICIDS2017 classification
    # =====================================================

    if (
        isinstance(
            ml_features,
            dict,
        )
        and ml_features
    ):
        try:
            xgb_result = (
                service.predict_network_attack_xgboost(
                    ml_features
                )
            )

        except Exception as exc:
            errors["xgboost"] = str(
                exc
            )

    # =====================================================
    # 3. Isolation Forest - Suricata anomaly detection
    # =====================================================

    if (
        isinstance(
            suricata_event,
            dict,
        )
        and suricata_event
    ):
        try:
            anomaly_event = dict(
                suricata_event
            )

            anomaly_event[
                "event_type"
            ] = "flow"

            isolation_result = (
                service.detect_suricata_anomaly(
                    anomaly_event
                )
            )

        except Exception:
            errors[
                "isolation_forest"
            ] = "Isolation Forest analysis failed"

    # =====================================================
    # 4. No usable ML input
    # =====================================================

    if (
        rf_result is None
        and xgb_result is None
        and isolation_result is None
    ):
        return {
            "ml_analysis": {
                "status": (
                    "failed"
                    if errors
                    else "not_available"
                ),
                "prediction": None,
                "reason": (
                    "No CICIDS2017 feature vector "
                    "or Suricata network event "
                    "was provided for this incident."
                    if not errors
                    else None
                ),
                "errors": (
                    errors
                    if errors
                    else None
                ),
            },

            "agent_trace": [
                "Machine Learning"
            ],
        }

    # =====================================================
    # 5. Build combined ML result
    # =====================================================

    available_engines = []

    if rf_result is not None:
        available_engines.append(
            "random_forest"
        )

    if xgb_result is not None:
        available_engines.append(
            "xgboost"
        )

    if isolation_result is not None:
        available_engines.append(
            "isolation_forest"
        )

    # -----------------------------------------------------
    # Top-level prediction
    #
    # Priority:
    # - supervised classifiers when available
    # - otherwise Isolation Forest
    # -----------------------------------------------------

    prediction = None

    if xgb_result is not None:
        prediction = xgb_result.get(
            "prediction"
        )

    elif rf_result is not None:
        prediction = rf_result.get(
            "prediction"
        )

    elif isolation_result is not None:
        prediction = (
            isolation_result.get(
                "prediction"
            )
        )

    ml_analysis = {
        "status": "success",
        "engine": (
            available_engines[0]
            if len(available_engines) == 1
            else "hybrid"
        ),
        "prediction": prediction,
        "engines": available_engines,
        "random_forest": rf_result,
        "xgboost": xgb_result,
        "isolation_forest": (
            isolation_result
        ),
        "is_anomaly": (
            isolation_result.get(
                "is_anomaly"
            )
            if isolation_result
            else None
        ),
        "anomaly_score": (
            isolation_result.get(
                "anomaly_score"
            )
            if isolation_result
            else None
        ),
        "errors": (
            errors
            if errors
            else None
        ),
    }

    return {
        "ml_analysis": ml_analysis,

        "agent_trace": [
            "Machine Learning"
        ],
    }

def threat_intelligence_agent(
    state: SOCState,
) -> dict:
    """
    Extract and enrich IOCs from the primary incident
    and correlated incidents.

    Supported IOC types:
    - IP addresses
    - Domains
    - URLs
    - File hashes

    Threat Intelligence providers:
    - AbuseIPDB
    - VirusTotal
    - AlienVault OTX
    - MISP
    """

    incident = state.get(
        "incident",
        {},
    )

    correlated_incidents = state.get(
        "correlated_incidents",
        [],
    )

    ioc_extractor = IOCExtractor()
    enrichment_service = (
        ThreatIntelligenceEnrichmentService()
    )

    results = []

    candidate_ips = set()
    candidate_domains = set()
    candidate_urls = set()
    candidate_hashes = {}

    observations = {}

    # =====================================================
    # REGISTER OBSERVATION
    # =====================================================

    def register_observation(
        ioc_type,
        value,
        incident_data,
        role,
    ):
        key = (
            ioc_type,
            value,
        )

        if key not in observations:
            observations[key] = []

        observation = {
            "incident_id": incident_data.get(
                "id"
            ),
            "source": incident_data.get(
                "source"
            ),
            "role": role,
        }

        if observation not in observations[key]:
            observations[key].append(
                observation
            )

    # =====================================================
    # COLLECT IOCs FROM INCIDENT
    # =====================================================

    def collect_incident_iocs(
        incident_data,
        role,
    ):
        if not isinstance(
            incident_data,
            dict,
        ):
            return

        text = (
            f"{incident_data.get('title', '')} "
            f"{incident_data.get('description', '')}"
        )

        try:
            extracted = (
                ioc_extractor.extract_all(
                    text
                )
            )

        except Exception:
            print(
                "Threat Intelligence IOC extraction failed"
            )

            extracted = {
                "ips": [],
                "domains": [],
                "urls": [],
                "hashes": [],
            }

        # -------------------------------------------------
        # Explicit IP addresses
        # -------------------------------------------------

        explicit_ips = [
            incident_data.get(
                "source_ip"
            ),
            incident_data.get(
                "destination_ip"
            ),
        ]

        for ip_address in explicit_ips:

            if not ip_address:
                continue

            candidate_ips.add(
                ip_address
            )

            register_observation(
                "ip",
                ip_address,
                incident_data,
                role,
            )

        # -------------------------------------------------
        # Extracted IP addresses
        # -------------------------------------------------

        for ip_address in extracted.get(
            "ips",
            [],
        ):

            if not ip_address:
                continue

            candidate_ips.add(
                ip_address
            )

            register_observation(
                "ip",
                ip_address,
                incident_data,
                role,
            )

        # -------------------------------------------------
        # Domains
        # -------------------------------------------------

        for domain in extracted.get(
            "domains",
            [],
        ):

            if not domain:
                continue

            candidate_domains.add(
                domain
            )

            register_observation(
                "domain",
                domain,
                incident_data,
                role,
            )

        # -------------------------------------------------
        # URLs
        # -------------------------------------------------

        for url in extracted.get(
            "urls",
            [],
        ):

            if not url:
                continue

            candidate_urls.add(
                url
            )

            register_observation(
                "url",
                url,
                incident_data,
                role,
            )

        # -------------------------------------------------
        # Hashes
        # -------------------------------------------------

        for hash_data in extracted.get(
            "hashes",
            [],
        ):

            if not isinstance(
                hash_data,
                dict,
            ):
                continue

            file_hash = hash_data.get(
                "value"
            )

            hash_type = hash_data.get(
                "hash_type"
            )

            if not file_hash:
                continue

            candidate_hashes[
                file_hash
            ] = hash_type

            register_observation(
                "hash",
                file_hash,
                incident_data,
                role,
            )

    # =====================================================
    # PRIMARY INCIDENT
    # =====================================================

    collect_incident_iocs(
        incident,
        "primary",
    )

    # =====================================================
    # CORRELATED INCIDENTS
    # =====================================================

    for correlated in correlated_incidents:

        collect_incident_iocs(
            correlated,
            "correlated",
        )

    # =====================================================
    # IP ENRICHMENT
    # =====================================================

    for ip_address in sorted(
        candidate_ips
    ):

        result = (
            enrichment_service.enrich_ip(
                ip_address
            )
        )

        result["observed_in"] = (
            observations.get(
                (
                    "ip",
                    ip_address,
                ),
                [],
            )
        )

        results.append(
            result
        )

    # =====================================================
    # DOMAIN ENRICHMENT
    # =====================================================

    for domain in sorted(
        candidate_domains
    ):

        result = (
            enrichment_service.enrich_domain(
                domain
            )
        )

        result["observed_in"] = (
            observations.get(
                (
                    "domain",
                    domain,
                ),
                [],
            )
        )

        results.append(
            result
        )

    # =====================================================
    # URL ENRICHMENT
    # =====================================================

    for url in sorted(
        candidate_urls
    ):

        result = (
            enrichment_service.enrich_url(
                url
            )
        )

        result["observed_in"] = (
            observations.get(
                (
                    "url",
                    url,
                ),
                [],
            )
        )

        results.append(
            result
        )

    # =====================================================
    # HASH ENRICHMENT
    # =====================================================

    for file_hash in sorted(
        candidate_hashes
    ):

        hash_type = candidate_hashes[
            file_hash
        ]

        result = (
            enrichment_service.enrich_hash(
                file_hash,
                hash_type=hash_type,
            )
        )

        result["observed_in"] = (
            observations.get(
                (
                    "hash",
                    file_hash,
                ),
                [],
            )
        )

        results.append(
            result
        )

    # =====================================================
    # RESPONSE
    # =====================================================

    return {
        "threat_intelligence": results,

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

    # =====================================================
    # RAG SEARCH
    # =====================================================

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

    except Exception:
        print(
            "RAG search failed"
        )

        rag_context = []

        # =====================================================
    # MACHINE LEARNING CONTEXT
    # =====================================================

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

        random_forest = ml_analysis.get(
            "random_forest"
        ) or {}

        xgboost = ml_analysis.get(
            "xgboost"
        ) or {}

        isolation_forest = ml_analysis.get(
            "isolation_forest"
        ) or {}

        ml_context = [
            {
                "source": "machine_learning",

                # -------------------------------------------------
                # Global supervised prediction
                # -------------------------------------------------
                "prediction": (
                    ml_analysis.get(
                        "prediction"
                    )
                ),

                # -------------------------------------------------
                # Random Forest
                # -------------------------------------------------
                "random_forest_prediction": (
                    random_forest.get(
                        "prediction"
                    )
                ),

                "random_forest_benign_probability": (
                    random_forest.get(
                        "benign_probability"
                    )
                ),

                "random_forest_ddos_probability": (
                    random_forest.get(
                        "ddos_probability"
                    )
                ),

                "random_forest_portscan_probability": (
                    random_forest.get(
                        "portscan_probability"
                    )
                ),

                "random_forest_ftp_patator_probability": (
                    random_forest.get(
                        "ftp_patator_probability"
                    )
                ),

                "random_forest_ssh_patator_probability": (
                    random_forest.get(
                        "ssh_patator_probability"
                    )
                ),

                # -------------------------------------------------
                # XGBoost
                # -------------------------------------------------
                "xgboost_prediction": (
                    xgboost.get(
                        "prediction"
                    )
                ),

                "xgboost_benign_probability": (
                    xgboost.get(
                        "benign_probability"
                    )
                ),

                "xgboost_ddos_probability": (
                    xgboost.get(
                        "ddos_probability"
                    )
                ),

                "xgboost_portscan_probability": (
                    xgboost.get(
                        "portscan_probability"
                    )
                ),

                "xgboost_ftp_patator_probability": (
                    xgboost.get(
                        "ftp_patator_probability"
                    )
                ),

                "xgboost_ssh_patator_probability": (
                    xgboost.get(
                        "ssh_patator_probability"
                    )
                ),

                # -------------------------------------------------
                # Isolation Forest
                # -------------------------------------------------
                "isolation_forest_prediction": (
                    isolation_forest.get(
                        "prediction"
                    )
                ),

                "is_anomaly": (
                    ml_analysis.get(
                        "is_anomaly"
                    )
                ),

                "anomaly_score": (
                    ml_analysis.get(
                        "anomaly_score"
                    )
                ),
            }
        ]

    # =====================================================
    # CORRELATED MULTI-SOURCE EVIDENCE
    # =====================================================

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

    # =====================================================
    # MULTI-SOURCE CORRELATION CONFIDENCE
    # =====================================================

    detected_sources = set()

    primary_source = incident.get(
        "source"
    )

    if primary_source:
        detected_sources.add(
            str(primary_source)
        )

    for correlated in correlated_incidents:

        if not isinstance(
            correlated,
            dict,
        ):
            continue

        correlated_source = (
            correlated.get(
                "source"
            )
        )

        if correlated_source:
            detected_sources.add(
                str(correlated_source)
            )

    source_count = len(
        detected_sources
    )

        # =====================================================
    # MULTI-SOURCE CORRELATION CONFIDENCE
    # =====================================================

    correlation_summary = (
        CorrelationService.build_correlation_summary(
            incident=incident,
            correlated_incidents=correlated_incidents,
        )
    )

    correlation_confidence = (
        correlation_summary.get(
            "confidence",
            "single_source",
        )
    )

    # =====================================================
    # FINAL INVESTIGATION CONTEXT
    # =====================================================

    investigation_context = (
        rag_context
        + ml_context
        + correlation_context
        + [
            correlation_summary
        ]
    )

    # =====================================================
    # LLM ANALYSIS
    # =====================================================

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

    # =====================================================
    # ADD ML RESULT
    # =====================================================

    result["ml_analysis"] = (
        ml_analysis
    )

    # =====================================================
    # ADD MULTI-SOURCE CORRELATION INFORMATION
    # =====================================================

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

    result["correlated_sources"] = (
        sorted(
            detected_sources
        )
    )

    result["correlation_confidence"] = (
        correlation_confidence
    )

    # =====================================================
    # MITRE ATT&CK VALIDATION
    # =====================================================

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

        except Exception:
            mitre_validation = {
                "technique_id": mitre_id,
                "name": None,
                "description": None,
                "valid": False,
                "error": "MITRE technique validation failed",
            }

    else:

        mitre_validation = {
            "technique_id": None,
            "name": None,
            "description": None,
            "valid": False,
        }

    return {
        "investigation": (
            result
        ),

        # Keep the complete enriched context
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
                incident.get(
                    "id"
                )
            ),

            "title": (
                incident.get(
                    "title"
                )
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

        "approved": (
            approved
        ),

        "status": (
            "approved"
            if approved
            else "rejected"
        ),

        "comment": (
            comment
        ),
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

    action_type = (
        "create_ticket"
    )

    # =====================================================
    # DETERMINE ACTION TYPE
    # =====================================================

    if "isolate" in recommendation_lower:

        action_type = (
            "isolate_endpoint"
        )

    elif (
        "block"
        in recommendation_lower
        and "ip"
        in recommendation_lower
    ):

        action_type = (
            "block_ip"
        )

    elif (
        "disable"
        in recommendation_lower
        and (
            "user"
            in recommendation_lower
            or "account"
            in recommendation_lower
        )
    ):

        action_type = (
            "disable_user"
        )

    elif (
        "notify"
        in recommendation_lower
        or "notification"
        in recommendation_lower
    ):

        action_type = (
            "send_notification"
        )

    # =====================================================
    # ISOLATE ENDPOINT
    # =====================================================

    if action_type == "isolate_endpoint":

        target = (
            incident.get(
                "hostname"
            )
            or incident.get(
                "endpoint"
            )
            or incident.get(
                "device_name"
            )
            or incident.get(
                "target"
            )
        )

        if not SOARService.is_safe_endpoint_target(
            target
        ):

            action_type = (
                "create_ticket"
            )

            target = (
                incident.get(
                    "hostname"
                )
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
            incident.get(
                "ip_address"
            )
            or incident.get(
                "source_ip"
            )
            or incident.get(
                "src_ip"
            )
            or incident.get(
                "ip"
            )
            or incident.get(
                "target"
            )
        )

        if not SOARService.is_safe_ip_target(
            target
        ):

            action_type = (
                "create_ticket"
            )

            target = (
                incident.get(
                    "hostname"
                )
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
            incident.get(
                "username"
            )
            or incident.get(
                "user"
            )
            or incident.get(
                "account"
            )
            or incident.get(
                "target"
            )
        )

        if not target:

            action_type = (
                "create_ticket"
            )

            target = (
                incident.get(
                    "hostname"
                )
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
            incident.get(
                "hostname"
            )
            or incident.get(
                "endpoint"
            )
            or incident.get(
                "target"
            )
            or (
                f"incident-"
                f"{incident.get('id', 'unknown')}"
            )
        )

    # =====================================================
    # FINAL SAFETY FALLBACK
    # =====================================================

    if not target:

        action_type = (
            "create_ticket"
        )

        target = (
            f"incident-"
            f"{incident.get('id', 'unknown')}"
        )

    return {
        "incident_id": (
            incident.get(
                "id"
            )
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
        ai_risk
        in {
            "high",
            "critical",
        }
        or incident_severity
        in {
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

        "risk_level": (
            ai_risk
        ),

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
        "response": (
            response
        ),

        "soar_action": (
            soar_action
        ),

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
        item.get(
            "source"
        )
        for item in rag_context
        if (
            isinstance(
                item,
                dict,
            )
            and item.get(
                "source"
            )
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

        # =================================================
        # MACHINE LEARNING
        # =================================================

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
            "random_forest": (
                ml_analysis.get(
                    "random_forest"
                )
                or {}
            ),

            "xgboost": (
                ml_analysis.get(
                    "xgboost"
                )
                or {}
            ),

            "isolation_forest": (
                ml_analysis.get(
                    "isolation_forest"
                )
                or {}
            ),
        },

        # =================================================
        # MITRE ATT&CK
        # =================================================

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

        # =================================================
        # RESPONSE
        # =================================================

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

        # =================================================
        # MULTI-SOURCE CORRELATION
        # =================================================

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

        "correlation_confidence": (
            investigation.get(
                "correlation_confidence",
                "single_source",
            )
        ),
    }

    return {
        "report": (
            report
        ),

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