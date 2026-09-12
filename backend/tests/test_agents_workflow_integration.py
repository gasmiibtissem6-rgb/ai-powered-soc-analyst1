from types import SimpleNamespace

from app.api import agents
from app.api.agents import (
    HumanDecision,
    resume_soc_workflow,
    run_soc_workflow,
)
from app.models.ai_analysis import AIAnalysis
from app.models.incident import Incident
from app.models.report import SOCReport
from app.models.soar_action import SOARAction


# =========================================================
# FAKE SQLALCHEMY QUERY
# =========================================================

class FakeQuery:
    def __init__(
        self,
        session,
        model,
    ):
        self.session = session
        self.model = model

    def filter(
        self,
        *args,
        **kwargs,
    ):
        return self

    def order_by(
        self,
        *args,
        **kwargs,
    ):
        return self

    def first(self):
        if self.model is Incident:
            return self.session.incident

        # Persistence helpers first check whether a result
        # already exists for the thread/action.
        return None

    def all(self):
        # No correlated incidents in this scenario.
        return []


# =========================================================
# FAKE SQLALCHEMY SESSION
# =========================================================

class FakeSession:
    def __init__(
        self,
        incident,
    ):
        self.incident = incident

        self.added = []
        self.commits = 0
        self.rollbacks = 0

        self._ids = {
            AIAnalysis: 101,
            SOCReport: 201,
            SOARAction: 301,
        }

    def query(
        self,
        model,
    ):
        return FakeQuery(
            self,
            model,
        )

    def add(
        self,
        obj,
    ):
        self.added.append(
            obj
        )

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def refresh(
        self,
        obj,
    ):
        if (
            getattr(
                obj,
                "id",
                None,
            )
            is None
        ):
            object_id = self._ids.get(
                type(obj)
            )

            if object_id is not None:
                obj.id = object_id


# =========================================================
# FAKE LANGGRAPH
# =========================================================

class FakeSOCGraph:
    def __init__(
        self,
        incident_id,
    ):
        self.incident_id = (
            incident_id
        )

        self.invoke_calls = []
        self.thread_id = None

    def invoke(
        self,
        payload,
        config=None,
    ):
        self.invoke_calls.append(
            {
                "payload": payload,
                "config": config,
            }
        )

        # -------------------------------------------------
        # FIRST RUN
        # -------------------------------------------------

        if len(
            self.invoke_calls
        ) == 1:
            self.thread_id = (
                config[
                    "configurable"
                ][
                    "thread_id"
                ]
            )

            return {
                "incident": {
                    "id": self.incident_id,
                    "title": (
                        "HITL integration incident"
                    ),
                    "description": (
                        "Suspicious SSH activity"
                    ),
                    "severity": "critical",
                    "status": "open",
                    "source": "Wazuh",
                    "hostname": (
                        "integration-host"
                    ),
                    "source_ip": (
                        "203.0.113.50"
                    ),
                    "destination_ip": (
                        "10.0.0.20"
                    ),
                    "username": "root",
                    "correlation_id": None,
                },

                "correlated_incidents": [],

                "triage": {
                    "severity": "critical",
                },

                "ml_analysis": {
                    "random_forest": {
                        "prediction": (
                            "SSH-Patator"
                        ),
                        "benign_probability": (
                            0.02
                        ),
                        "ddos_probability": (
                            0.01
                        ),
                        "portscan_probability": (
                            0.02
                        ),
                        "ftp_patator_probability": (
                            0.05
                        ),
                        "ssh_patator_probability": (
                            0.90
                        ),
                    },

                    "xgboost": {
                        "prediction": (
                            "SSH-Patator"
                        ),
                        "benign_probability": (
                            0.01
                        ),
                        "ddos_probability": (
                            0.01
                        ),
                        "portscan_probability": (
                            0.01
                        ),
                        "ftp_patator_probability": (
                            0.02
                        ),
                        "ssh_patator_probability": (
                            0.95
                        ),
                    },

                    "isolation_forest": {
                        "prediction": (
                            "anomaly"
                        ),
                        "is_anomaly": True,
                        "anomaly_score": (
                            -0.42
                        ),
                    },
                },

                "threat_intelligence": {
                    "risk": "high",
                },

                "rag_context": [
                    {
                        "source": (
                            "nist-runbook"
                        ),
                        "score": 0.94,
                    },
                    {
                        "source": (
                            "mitre-attack"
                        ),
                        "score": 0.91,
                    },
                ],

                "investigation": {
                    "summary": (
                        "Repeated SSH brute-force "
                        "activity was detected."
                    ),
                    "risk_level": (
                        "critical"
                    ),
                    "explanation": (
                        "The source generated "
                        "multiple authentication "
                        "failures."
                    ),
                    "recommendation": (
                        "Block the source IP "
                        "and investigate the host."
                    ),
                    "mitre_technique": (
                        "T1110"
                    ),
                },

                "mitre_validation": {
                    "technique_id": (
                        "T1110"
                    ),
                    "name": (
                        "Brute Force"
                    ),
                    "description": (
                        "Adversaries may use "
                        "brute-force techniques."
                    ),
                    "valid": True,
                },

                "agent_trace": [
                    "triage_agent",
                    "ml_agent",
                    "threat_intel_agent",
                    "rag_agent",
                    "investigation_agent",
                    "human_review_agent",
                ],

                "__interrupt__": [
                    SimpleNamespace(
                        value={
                            "message": (
                                "Human approval "
                                "required"
                            ),
                            "incident_id": (
                                self.incident_id
                            ),
                        }
                    )
                ],
            }

        # -------------------------------------------------
        # RESUMED / COMPLETED RUN
        # -------------------------------------------------

        return {
            "incident": {
                "id": self.incident_id,
                "title": (
                    "HITL integration incident"
                ),
                "description": (
                    "Suspicious SSH activity"
                ),
                "severity": "critical",
                "status": "open",
                "source": "Wazuh",
                "hostname": (
                    "integration-host"
                ),
                "source_ip": (
                    "203.0.113.50"
                ),
                "destination_ip": (
                    "10.0.0.20"
                ),
                "username": "root",
                "correlation_id": None,
            },

            "correlated_incidents": [],

            "triage": {
                "severity": "critical",
            },

            "ml_analysis": {
                "status": "completed",

                "random_forest": {
                    "prediction": (
                        "SSH-Patator"
                    ),
                    "benign_probability": (
                        0.02
                    ),
                    "ddos_probability": (
                        0.01
                    ),
                    "portscan_probability": (
                        0.02
                    ),
                    "ftp_patator_probability": (
                        0.05
                    ),
                    "ssh_patator_probability": (
                        0.90
                    ),
                },

                "xgboost": {
                    "prediction": (
                        "SSH-Patator"
                    ),
                    "benign_probability": (
                        0.01
                    ),
                    "ddos_probability": (
                        0.01
                    ),
                    "portscan_probability": (
                        0.01
                    ),
                    "ftp_patator_probability": (
                        0.02
                    ),
                    "ssh_patator_probability": (
                        0.95
                    ),
                },

                "isolation_forest": {
                    "prediction": (
                        "anomaly"
                    ),
                    "is_anomaly": True,
                    "anomaly_score": (
                        -0.42
                    ),
                },
            },

            "threat_intelligence": {
                "risk": "high",
            },

            "rag_context": [
                {
                    "source": (
                        "nist-runbook"
                    ),
                    "score": 0.94,
                },
                {
                    "source": (
                        "mitre-attack"
                    ),
                    "score": 0.91,
                },
            ],

            "investigation": {
                "summary": (
                    "Repeated SSH brute-force "
                    "activity was detected."
                ),
                "risk_level": (
                    "critical"
                ),
                "explanation": (
                    "The source generated "
                    "multiple failed "
                    "authentication attempts."
                ),
                "recommendation": (
                    "Block the source IP "
                    "and investigate the host."
                ),
                "mitre_technique": (
                    "T1110"
                ),
            },

            "mitre_validation": {
                "technique_id": (
                    "T1110"
                ),
                "name": (
                    "Brute Force"
                ),
                "description": (
                    "Adversaries may use "
                    "brute-force techniques."
                ),
                "valid": True,
            },

            "human_review": {
                "required": True,
                "approved": True,
                "status": "approved",
                "comment": (
                    "Approved by SOC administrator"
                ),
            },

            "response": {
                "status": "approved",
            },

            "soar_action": {
                "incident_id": (
                    self.incident_id
                ),
                "action_type": (
                    "block_ip"
                ),
                "target": (
                    "203.0.113.50"
                ),
                "status": "approved",
                "requires_approval": True,
            },

            "report": {
                "title": (
                    "SOC Investigation Report"
                ),
                "summary": (
                    "Critical SSH brute-force "
                    "incident investigated."
                ),
                "risk_level": (
                    "critical"
                ),
                "recommendation": (
                    "Block the malicious "
                    "source IP."
                ),
                "response_status": (
                    "approved"
                ),
            },

            "agent_trace": [
                "triage_agent",
                "ml_agent",
                "threat_intel_agent",
                "rag_agent",
                "investigation_agent",
                "human_review_agent",
                "response_agent",
                "report_agent",
            ],
        }

    def get_state(
        self,
        config,
    ):
        return SimpleNamespace(
            values={
                "incident": {
                    "id": (
                        self.incident_id
                    ),
                    "title": (
                        "HITL integration incident"
                    ),
                    "description": (
                        "Suspicious SSH activity"
                    ),
                    "severity": "critical",
                    "status": "open",
                    "source": "Wazuh",
                    "source_ip": (
                        "203.0.113.50"
                    ),
                },

                "investigation": {
                    "summary": (
                        "Repeated SSH brute-force "
                        "activity was detected."
                    ),
                    "risk_level": (
                        "critical"
                    ),
                },
            },

            # Non-empty means LangGraph is currently
            # waiting for human continuation.
            next=(
                "human_review",
            ),
        )


# =========================================================
# TEST
# =========================================================

def test_hitl_workflow_resume_persists_results(
    monkeypatch,
):
    incident = Incident(
        id=9001,
        title=(
            "HITL integration incident"
        ),
        description=(
            "Suspicious SSH activity"
        ),
        severity="critical",
        status="open",
        source="Wazuh",
        hostname="integration-host",
        source_ip="203.0.113.50",
        destination_ip="10.0.0.20",
        username="root",
        workflow_status="pending",
        correlation_id=None,
    )

    db = FakeSession(
        incident
    )

    fake_graph = FakeSOCGraph(
        incident_id=incident.id
    )

    monkeypatch.setattr(
        agents,
        "soc_graph",
        fake_graph,
    )

    # =====================================================
    # 1. START WORKFLOW
    # =====================================================

    waiting_result = (
        run_soc_workflow(
            db=db,
            incident=incident,
        )
    )

    assert (
        waiting_result["status"]
        == "waiting_for_human"
    )

    assert (
        waiting_result["thread_id"]
        == fake_graph.thread_id
    )

    assert (
        incident.workflow_status
        == "waiting_for_human"
    )

    assert (
        incident.workflow_error
        is None
    )

    assert len(
        waiting_result["interrupt"]
    ) == 1

    # No final persistence must occur
    # before human approval.
    assert not any(
        isinstance(
            obj,
            AIAnalysis,
        )
        for obj in db.added
    )

    assert not any(
        isinstance(
            obj,
            SOCReport,
        )
        for obj in db.added
    )

    assert not any(
        isinstance(
            obj,
            SOARAction,
        )
        for obj in db.added
    )

    # =====================================================
    # 2. RESUME AFTER HUMAN APPROVAL
    # =====================================================

    decision = HumanDecision(
        approved=True,
        comment=(
            "Approved by SOC administrator"
        ),
    )

    completed_result = (
        resume_soc_workflow(
            thread_id=(
                waiting_result[
                    "thread_id"
                ]
            ),
            decision=decision,
            db=db,
            current_user=None,
        )
    )

    # =====================================================
    # 3. FINAL WORKFLOW STATE
    # =====================================================

    assert (
        completed_result["status"]
        == "completed"
    )

    assert (
        completed_result["thread_id"]
        == waiting_result["thread_id"]
    )

    assert (
        incident.workflow_status
        == "completed"
    )

    assert (
        incident.workflow_error
        is None
    )

    # =====================================================
    # 4. PERSISTED AI ANALYSIS
    # =====================================================

    analyses = [
        obj
        for obj in db.added
        if isinstance(
            obj,
            AIAnalysis,
        )
    ]

    assert len(
        analyses
    ) == 1

    analysis = analyses[0]

    assert (
        analysis.id
        == 101
    )

    assert (
        analysis.incident_id
        == incident.id
    )

    assert (
        analysis.thread_id
        == waiting_result["thread_id"]
    )

    assert (
        analysis.risk_level
        == "critical"
    )

    assert (
        analysis.mitre_technique
        == "T1110"
    )

    assert (
        analysis.mitre_valid
        is True
    )

    assert (
        analysis.human_approval_required
        is True
    )

    assert (
        analysis.human_approved
        is True
    )

    assert (
        analysis.human_review_status
        == "approved"
    )

    assert (
        analysis.human_comment
        == "Approved by SOC administrator"
    )

    assert (
        analysis.rag_sources
        == [
            "nist-runbook",
            "mitre-attack",
        ]
    )

    # =====================================================
    # 5. PERSISTED SOC REPORT
    # =====================================================

    reports = [
        obj
        for obj in db.added
        if isinstance(
            obj,
            SOCReport,
        )
    ]

    assert len(
        reports
    ) == 1

    report = reports[0]

    assert (
        report.id
        == 201
    )

    assert (
        report.incident_id
        == incident.id
    )

    assert (
        report.ai_analysis_id
        == analysis.id
    )

    assert (
        report.thread_id
        == waiting_result["thread_id"]
    )

    assert (
        report.risk_level
        == "critical"
    )

    assert (
        report.mitre_technique
        == "T1110"
    )

    assert (
        report.human_review_status
        == "approved"
    )

    assert (
        report.human_comment
        == "Approved by SOC administrator"
    )

    assert (
        report.rag_sources
        == [
            "nist-runbook",
            "mitre-attack",
        ]
    )

    # =====================================================
    # 6. PERSISTED SOAR ACTION
    # =====================================================

    actions = [
        obj
        for obj in db.added
        if isinstance(
            obj,
            SOARAction,
        )
    ]

    assert len(
        actions
    ) == 1

    action = actions[0]

    assert (
        action.id
        == 301
    )

    assert (
        action.incident_id
        == incident.id
    )

    assert (
        action.action_type
        == "block_ip"
    )

    assert (
        action.target
        == "203.0.113.50"
    )

    assert (
        action.requires_approval
        is True
    )

    assert (
        action.approved
        is True
    )

    assert (
        action.status
        == "approved"
    )

    # =====================================================
    # 7. RESPONSE REFERENCES PERSISTED OBJECTS
    # =====================================================

    assert (
        completed_result[
            "ai_analysis_id"
        ]
        == analysis.id
    )

    assert (
        completed_result[
            "soc_report_id"
        ]
        == report.id
    )

    assert (
        completed_result[
            "soar_action_id"
        ]
        == action.id
    )

    # Start + resume.
    assert len(
        fake_graph.invoke_calls
    ) == 2

    assert (
        db.rollbacks
        == 0
    )