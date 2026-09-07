# AI-Powered SOC Analyst — User Guide

## 1. Introduction

This guide explains how to use the AI-Powered SOC Analyst prototype from the perspective of SOC analysts and administrators.

The current validated prototype is primarily accessed through the FastAPI REST API and Swagger UI.

The platform provides capabilities for:

- authentication
- alert management
- incident management
- Wazuh and Suricata ingestion
- Machine Learning analysis
- Threat Intelligence enrichment
- AI-assisted investigation
- RAG-assisted analyst queries
- MITRE ATT&CK mapping
- LangGraph multi-agent analysis
- Human-in-the-Loop validation
- SOC report generation
- SOAR response management
- SOC metrics

The frontend dashboard is a separate project component and is not required to use the backend API.

---

## 2. Accessing the Platform

In the validated Docker environment, the backend is exposed through Traefik using HTTPS.

Main backend URL:

```text
https://soc.local
```

Swagger UI:

```text
https://soc.local/docs
```

OpenAPI schema:

```text
https://soc.local/openapi.json
```

Health endpoint:

```text
https://soc.local/health
```

The HTTPS route has been validated through the Traefik reverse proxy.

---

## 3. Swagger UI

Swagger UI provides an interactive interface for exploring and testing the REST API.

Open:

```text
https://soc.local/docs
```

Swagger displays the available API groups, including:

```text
Authentication
Alerts
Incidents
AI Analysis
Machine Learning
Threat Intelligence
MITRE ATT&CK
SOC Agents
SOAR
Wazuh
Suricata
SOC Reports
Analyst Assistant
Metrics
```

The live OpenAPI schema is the authoritative reference for exact request and response models.

---

## 4. User Roles

The backend uses Role-Based Access Control (RBAC).

The main application roles are:

```text
analyst
admin
```

An analyst can access normal SOC investigation functionality according to the permissions enforced by the backend.

An administrator has additional privileges for security-sensitive operations.

---

## 5. Analyst Responsibilities

The analyst role is intended for daily SOC investigation activities.

Typical analyst tasks include:

- reviewing alerts
- reviewing incidents
- requesting Threat Intelligence
- examining ML results
- generating AI analyses
- launching multi-agent investigation
- consulting MITRE ATT&CK information
- using the analyst assistant
- reviewing generated SOC reports
- creating permitted SOAR actions

Authorization remains enforced by the backend.

---

## 6. Administrator Responsibilities

Administrative authorization is required for more sensitive operations.

Examples include:

- resuming interrupted high-risk workflows
- approving SOAR actions
- rejecting SOAR actions
- executing approved SOAR actions
- managing security-sensitive workflow decisions

The administrator therefore represents an additional control boundary.

---

## 7. Authentication

Local authentication endpoints are:

```http
POST /auth/register
POST /auth/login
GET  /auth/me
```

The backend also supports Keycloak-based OIDC authentication.

Protected API endpoints require a valid authentication token.

---

## 8. Local Login

To authenticate using the local authentication mechanism, use:

```http
POST /auth/login
```

The successful response provides an access token.

The token is then supplied to protected requests using:

```text
Authorization: Bearer <access_token>
```

Never share or commit authentication tokens.

---

## 9. Checking the Current User

After authentication, the current user can be checked through:

```http
GET /auth/me
```

This can be used to verify the authenticated identity and role.

---

## 10. Keycloak Authentication

The backend also supports Keycloak as an OIDC identity provider.

The validated prototype includes:

```text
Keycloak realm: soc
Client: soc-backend
```

Backend authorization accepts supported Keycloak access tokens.

For a future browser frontend, the recommended authentication flow is:

```text
Authorization Code + PKCE
```

Credentials and tokens must not be embedded in frontend source code.

---

# Alerts and Incidents

## 11. Alerts

Alerts represent security observations received or created by the platform.

Available endpoints include:

```http
POST   /alerts
GET    /alerts
GET    /alerts/{alert_id}
PUT    /alerts/{alert_id}
DELETE /alerts/{alert_id}
```

---

## 12. Viewing Alerts

To list alerts:

```http
GET /alerts
```

To inspect one alert:

```http
GET /alerts/{alert_id}
```

The analyst should review alert information before interpreting it as a confirmed security incident.

---

## 13. Incidents

Incidents represent structured security cases that can be investigated by the SOC workflow.

Endpoints:

```http
GET    /incidents
POST   /incidents
GET    /incidents/correlation/{correlation_id}
GET    /incidents/{incident_id}
PUT    /incidents/{incident_id}
DELETE /incidents/{incident_id}
```

---

## 14. Viewing Incidents

To list incidents:

```http
GET /incidents
```

To inspect a specific incident:

```http
GET /incidents/{incident_id}
```

The incident identifier is used by several downstream functions such as:

```text
AI Analysis
Threat Intelligence
LangGraph analysis
Reports
```

---

## 15. Incident Correlation

Related incidents can share a correlation identifier.

To inspect correlated incidents:

```http
GET /incidents/correlation/{correlation_id}
```

Correlation helps the analyst investigate multiple related observations as part of a broader security context.

---

# Security Event Ingestion

## 16. Wazuh Alerts

Wazuh alerts can be ingested through:

```http
POST /wazuh/alerts
```

This endpoint is intended for trusted ingestion rather than normal interactive user activity.

---

## 17. Suricata Alerts

Suricata EVE JSON alerts can be ingested through:

```http
POST /suricata/alerts
```

Suricata provides network IDS/IPS evidence that can become part of incident investigation.

---

## 18. Ingestion Authentication

Wazuh and Suricata ingestion endpoints are protected with a dedicated ingestion API key.

The request uses:

```text
X-SOC-Ingestion-Key
```

This credential is separate from normal analyst authentication.

Users must never expose the real ingestion key in screenshots, source code, documentation, or Git commits.

---

# Machine Learning

## 19. Network Attack Prediction

The Machine Learning API exposes:

```http
POST /ml/predict
```

This endpoint performs supervised network attack analysis using the project's trained ML pipeline.

The current hybrid architecture includes:

```text
Random Forest
XGBoost
Isolation Forest
```

---

## 20. Suricata Anomaly Detection

Suricata anomaly analysis is available through:

```http
POST /ml/suricata-anomaly
```

Isolation Forest provides anomaly evidence for network behavior.

An anomaly result is supporting evidence and must not automatically be interpreted as proof of an attack.

---

## 21. Interpreting ML Results

An investigation can contain disagreement between models.

Example:

```text
Random Forest    -> BENIGN
XGBoost          -> BENIGN
Isolation Forest -> ANOMALY
```

The analyst should interpret these results together with:

```text
incident context
Suricata/Wazuh evidence
Threat Intelligence
correlation
RAG context
LLM reasoning
MITRE ATT&CK
```

ML output is decision-support evidence rather than an autonomous response authorization.

---

# Threat Intelligence

## 22. IP Reputation

Basic IP reputation is available through:

```http
GET /threat-intelligence/ip/{ip_address}
```

The primary service behind this endpoint uses AbuseIPDB.

---

## 23. VirusTotal

VirusTotal endpoints include:

```http
GET  /threat-intelligence/virustotal/ip/{ip_address}
GET  /threat-intelligence/virustotal/domain/{domain}
POST /threat-intelligence/virustotal/url
GET  /threat-intelligence/virustotal/hash/{file_hash}
```

These allow investigation of different indicator types.

---

## 24. AlienVault OTX

OTX endpoints include:

```http
GET  /threat-intelligence/otx/ip/{ip_address}
GET  /threat-intelligence/otx/domain/{domain}
POST /threat-intelligence/otx/url
GET  /threat-intelligence/otx/hash/{file_hash}
```

---

## 25. Incident Threat Intelligence

To enrich an incident:

```http
GET /threat-intelligence/incident/{incident_id}
```

This provides Threat Intelligence context associated with the incident.

---

## 26. Interpreting Threat Intelligence

A reputation result should be treated as evidence.

For example:

```text
SAFE
SUSPICIOUS
MALICIOUS
UNKNOWN
```

does not independently determine the final incident severity.

The analyst should combine provider results with local telemetry and other investigation evidence.

---

## 27. MISP Status

MISP support exists as an optional backend provider.

However, MISP is not configured in the current prototype environment.

Therefore analysts should not expect active MISP enrichment in the current deployment.

---

# AI Analysis

## 28. Generating AI Analysis

AI-assisted incident analysis can be generated using:

```http
POST /ai-analysis/generate/{incident_id}
```

The current prototype uses:

```text
Provider: Groq
Model: openai/gpt-oss-120b
```

---

## 29. AI Analysis Result

The AI analysis can contain:

```text
summary
risk level
explanation
recommendation
MITRE ATT&CK technique
```

The result is persisted and linked to the incident.

---

## 30. Viewing AI Analyses

Available endpoints are:

```http
GET /ai-analysis
GET /ai-analysis/incident/{incident_id}
GET /ai-analysis/{analysis_id}
```

These endpoints allow analysts to review previously generated analyses.

---

## 31. AI Analysis Management

The backend also exposes:

```http
POST   /ai-analysis
PUT    /ai-analysis/{analysis_id}
DELETE /ai-analysis/{analysis_id}
```

Actual access remains subject to backend authorization.

---

## 32. Interpreting AI Results

AI output must not be treated as guaranteed truth.

The analyst should compare the generated assessment with:

```text
original incident
ML results
Threat Intelligence
RAG sources
MITRE ATT&CK
correlation context
other telemetry
```

The AI layer assists the analyst but does not replace security judgment.

---

# MITRE ATT&CK

## 33. MITRE Technique Lookup

MITRE ATT&CK techniques can be inspected through:

```http
GET /mitre/technique/{technique_id}
```

Example:

```text
T1110
```

may correspond to:

```text
Brute Force
```

---

## 34. MITRE Validation

The LLM may propose a MITRE technique during analysis.

The backend MITRE service is used to validate technique information rather than relying only on generated text.

This improves consistency of the final investigation.

---

# Multi-Agent Investigation

## 35. Starting an Investigation

The LangGraph SOC workflow can be launched using:

```http
POST /agents/analyze/{incident_id}
```

The workflow can include:

```text
Triage
Machine Learning
Threat Intelligence
Investigation
Human Review
Response
Report
```

---

## 36. Investigation Flow

Conceptually:

```text
Incident
   |
   v
Triage
   |
   v
Machine Learning
   |
   v
Threat Intelligence
   |
   v
Investigation
   |
   v
Risk Decision
   |
   +---- Low / Medium ----> Continue
   |
   +---- High / Critical -> Human Review
```

---

# Human-in-the-Loop

## 37. Human Review

High or critical incidents can cause the workflow to pause.

The workflow may return a state indicating that human intervention is required.

Conceptually:

```text
waiting_for_human
```

At this stage, the analyst or administrator should review the investigation before allowing the workflow to continue.

---

## 38. What to Review Before Approval

Before approving a sensitive workflow, review:

- incident details
- severity
- source and destination information
- Wazuh/Suricata evidence
- ML results
- Threat Intelligence
- AI explanation
- MITRE mapping
- proposed recommendation
- potential operational impact

Approval should never be based only on the LLM recommendation.

---

## 39. Resuming the Workflow

An authorized administrator can resume an interrupted workflow through:

```http
POST /agents/resume/{thread_id}
```

The correct thread identifier from the interrupted analysis must be used.

The resume endpoint is admin-protected in the current prototype.

---

## 40. Rejecting Unsafe Recommendations

Human review exists partly to prevent unsafe automation.

If evidence does not justify the proposed response, the analyst should not approve a disruptive action.

The platform is designed so that:

```text
AI Recommendation != Human Approval
```

---

# SOC Reports

## 41. Reports

Completed investigations can produce structured SOC reports.

Available endpoints:

```http
GET /reports
GET /reports/incident/{incident_id}
GET /reports/{report_id}
```

---

## 42. Report Contents

A report can include information such as:

- incident details
- AI assessment
- risk level
- ML evidence
- Threat Intelligence
- MITRE ATT&CK
- RAG sources
- correlation information
- human review status
- response status
- agent execution trace

---

## 43. Reviewing Reports

Analysts should use reports as investigation summaries.

The report should be compared with the original telemetry when making important security decisions.

Generated reports improve traceability but do not replace source evidence.

---

# Analyst Assistant

## 44. Natural-Language Questions

The analyst assistant is exposed through:

```http
POST /analyst/ask
```

It allows cybersecurity-oriented natural-language questions to be answered with assistance from the project's AI/RAG layer.

---

## 45. Example Analyst Questions

Conceptual questions include:

```text
What is MITRE ATT&CK T1110?

How should repeated SSH authentication failures be investigated?

What evidence should I check for password spraying?

What response steps are appropriate for a suspicious source IP?
```

The exact request body should be taken from Swagger/OpenAPI.

---

## 46. Using Assistant Answers Safely

Assistant answers are advisory.

Do not:

- paste secrets into questions
- paste API keys
- paste authentication tokens
- treat generated answers as authorization
- execute destructive actions solely because the assistant recommends them

---

# SOAR

## 47. Viewing SOAR Actions

SOAR actions can be listed using:

```http
GET /soar
```

A specific action can be inspected using:

```http
GET /soar/{action_id}
```

---

## 48. Creating a SOAR Action

A permitted user can create an action through:

```http
POST /soar
```

Supported response concepts include:

```text
create_ticket
block_ip
isolate_endpoint
disable_user
send_notification
```

The exact request model is available in Swagger.

---

## 49. SOAR Approval

Sensitive SOAR actions require controlled approval.

Endpoint:

```http
POST /soar/{action_id}/approve
```

Approval is a security-sensitive operation and is restricted by RBAC.

---

## 50. SOAR Rejection

An inappropriate action can be rejected through:

```http
POST /soar/{action_id}/reject
```

Rejection prevents the proposed action from following the approved execution path.

---

## 51. SOAR Execution

Approved actions can use:

```http
POST /soar/{action_id}/execute
```

Execution remains subject to backend safety controls.

---

## 52. Dry-Run Mode

The current prototype uses:

```text
SOAR_EXECUTION_MODE=dry_run
```

Therefore SOAR is primarily used to safely demonstrate response orchestration.

Potentially destructive operations are not enabled by default.

---

## 53. SOAR Audit Logs

Action history can be inspected through:

```http
GET /soar/{action_id}/logs
```

The audit trail helps determine:

```text
when the action was created
whether it was approved or rejected
whether execution was requested
what simulation/execution result was recorded
```

---

## 54. Shuffle Status

Shuffle is not integrated into the current main prototype stack.

The working project uses its own internal SOAR implementation.

Therefore users should use the backend `/soar` endpoints rather than expecting a Shuffle workflow interface.

---

# Monitoring

## 55. Health Check

Backend health can be checked using:

```http
GET /health
```

The root endpoint is also available:

```http
GET /
```

---

## 56. SOC Metrics

Monitoring endpoints include:

```http
GET /metrics
GET /metrics/severity
GET /metrics/dashboard
```

These provide SOC-oriented operational information.

---

## 57. Prometheus Metrics

Prometheus-formatted metrics are exposed separately through:

```http
GET /prometheus
```

This endpoint is used by the monitoring infrastructure.

---

## 58. Grafana

Grafana is included in the Docker Compose prototype for visualization.

It can consume monitoring data exposed through Prometheus and backend metrics.

Grafana is an observability interface rather than the primary SOC investigation API.

---

# Recommended Investigation Procedure

## 59. Standard Analyst Workflow

A recommended investigation process is:

```text
1. Review Alert
        |
        v
2. Review/Create Incident
        |
        v
3. Check Correlation
        |
        v
4. Review ML Evidence
        |
        v
5. Enrich Indicators
        |
        v
6. Generate AI / Agent Analysis
        |
        v
7. Review RAG and MITRE Context
        |
        v
8. Validate Severity
        |
        v
9. Perform Human Review if Required
        |
        v
10. Review Response Recommendation
        |
        v
11. Approve/Reject SOAR Action
        |
        v
12. Review SOC Report and Audit Trail
```

---

## 60. High-Risk Investigation Procedure

For a high or critical incident:

```text
Do not immediately execute a response.

Review:
- original telemetry
- ML evidence
- Threat Intelligence
- AI reasoning
- MITRE mapping
- affected asset
- proposed response
- possible business impact
```

Only then should the authorized user decide whether the workflow or SOAR action should continue.

---

## 61. Handling Conflicting Evidence

Conflicting evidence is possible.

Example:

```text
ML classifier       -> BENIGN
Anomaly detector    -> ANOMALY
Threat Intelligence -> SAFE
Suricata            -> suspicious network behavior
```

The analyst should not discard any source automatically.

The correct decision depends on the complete incident context.

---

## 62. Handling Provider Failures

An external provider may temporarily fail.

Possible causes include:

```text
rate limit
timeout
quota
authentication failure
provider outage
```

A failed Threat Intelligence or LLM request should not automatically be interpreted as a safe result.

Instead, treat the evidence as unavailable and continue the investigation using available sources.

---

## 63. Handling UNKNOWN Reputation

A Threat Intelligence result of:

```text
UNKNOWN
```

does not mean:

```text
SAFE
```

It means that sufficient reputation evidence may not be available from that source.

---

# Security Recommendations

## 64. Never Expose Secrets

Never include the following in screenshots, reports, Git commits, prompts, or tickets:

```text
API keys
JWT tokens
passwords
Vault tokens
private keys
ingestion keys
database passwords
```

---

## 65. Do Not Commit `.env`

The real backend environment file:

```text
backend/.env
```

must remain outside Git.

Only:

```text
backend/.env.example
```

should contain safe placeholder values.

---

## 66. Use HTTPS

For the validated Docker deployment, use:

```text
https://soc.local
```

instead of sending credentials or tokens through an unsecured HTTP endpoint.

---

## 67. Respect RBAC

Do not attempt to bypass role restrictions.

RBAC exists to separate normal SOC analysis from privileged administrative actions.

---

## 68. Keep Human Control

AI, ML, Threat Intelligence, and RAG are analytical tools.

Security-sensitive operations remain controlled by:

```text
Authentication
RBAC
Human-in-the-Loop
SOAR approval
Execution policy
Audit logging
```

---

# Example End-to-End Usage

## 69. Example Workflow

A representative operational sequence is:

```text
Wazuh / Suricata Alert
        |
        v
Incident
        |
        v
Correlation
        |
        v
ML Analysis
        |
        v
Threat Intelligence
        |
        v
LangGraph Investigation
        |
        v
RAG + LLM
        |
        v
MITRE ATT&CK
        |
        v
High Risk?
   /          \
 No            Yes
 |              |
 |              v
 |         Human Review
 |              |
 +--------------+
        |
        v
Response
        |
        v
SOC Report
        |
        v
SOAR Action
        |
        v
Approval
        |
        v
Dry Run
        |
        v
Audit Log
```

---

## 70. Current Prototype Limitations

Users should be aware that:

- the frontend dashboard is a separate project component
- the backend API is the primary validated interaction layer
- MISP is not activated
- Shuffle is not integrated into the main stack
- SOAR destructive actions are disabled by default
- the current SOAR mode is dry-run
- not every attack category has been validated end-to-end
- AI results may contain errors
- ML results may contain false positives or false negatives
- Threat Intelligence providers may disagree or have missing data

---

## 71. Swagger as the API Reference

This guide explains the intended operational workflow.

For exact schemas, required parameters, request bodies, validation rules, and current endpoints, use:

```text
https://soc.local/docs
```

or:

```text
https://soc.local/openapi.json
```

The live OpenAPI schema should be considered authoritative if this guide and the running API differ.

---

## 72. User Guide Summary

The SOC analyst workflow follows the principle:

```text
Observe
   |
   v
Investigate
   |
   v
Enrich
   |
   v
Correlate
   |
   v
Analyze
   |
   v
Validate
   |
   v
Approve
   |
   v
Respond
   |
   v
Audit
```

The platform uses automation and artificial intelligence to accelerate investigation while maintaining human control over sensitive response decisions.