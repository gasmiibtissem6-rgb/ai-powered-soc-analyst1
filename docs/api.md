# AI-Powered SOC Analyst — API Documentation

## 1. Overview

The backend exposes a REST API built with FastAPI.

Interactive documentation is available at:

```text
https://soc.local/docs
```

OpenAPI schema:

```text
https://soc.local/openapi.json
```

Alternative documentation:

```text
https://soc.local/redoc
```

The following sections document the routes currently registered by the backend.

---

## 2. Authentication

### Register a user

```http
POST /auth/register
```

Creates a new local user account.

---

### Login

```http
POST /auth/login
```

Authenticates a local user and returns a JWT access token.

---

### Current user

```http
GET /auth/me
```

Returns information about the currently authenticated user.

---

## 3. Alerts

### Create alert

```http
POST /alerts
```

Creates a SOC alert.

---

### List alerts

```http
GET /alerts
```

Returns available alerts.

---

### Get alert

```http
GET /alerts/{alert_id}
```

Returns a specific alert.

---

### Update alert

```http
PUT /alerts/{alert_id}
```

Updates a specific alert.

---

### Delete alert

```http
DELETE /alerts/{alert_id}
```

Deletes a specific alert.

---

## 4. Incidents

### List incidents

```http
GET /incidents
```

Returns available incidents.

---

### Create incident

```http
POST /incidents
```

Creates a SOC incident.

---

### Get incidents by correlation ID

```http
GET /incidents/correlation/{correlation_id}
```

Returns incidents associated with a correlation identifier.

---

### Get incident

```http
GET /incidents/{incident_id}
```

Returns a specific incident.

---

### Update incident

```http
PUT /incidents/{incident_id}
```

Updates a specific incident.

---

### Delete incident

```http
DELETE /incidents/{incident_id}
```

Deletes a specific incident.

---

## 5. AI Analysis

### List AI analyses

```http
GET /ai-analysis
```

Returns stored AI analyses.

---

### Get analyses for an incident

```http
GET /ai-analysis/incident/{incident_id}
```

Returns AI analyses linked to a specific incident.

---

### Get AI analysis

```http
GET /ai-analysis/{analysis_id}
```

Returns a specific AI analysis.

---

### Create AI analysis

```http
POST /ai-analysis
```

Creates and stores an AI analysis.

---

### Update AI analysis

```http
PUT /ai-analysis/{analysis_id}
```

Updates a stored AI analysis.

---

### Delete AI analysis

```http
DELETE /ai-analysis/{analysis_id}
```

Deletes a stored AI analysis.

---

### Generate AI analysis

```http
POST /ai-analysis/generate/{incident_id}
```

Generates an AI-assisted analysis for an incident.

The analysis can include:

- summary
- risk level
- explanation
- recommendation
- MITRE ATT&CK technique

---

## 6. Machine Learning

### Network classification

```http
POST /ml/predict
```

Runs the supervised Machine Learning prediction pipeline.

The current prototype combines classification evidence from models such as:

- Random Forest
- XGBoost

---

### Suricata anomaly detection

```http
POST /ml/suricata-anomaly
```

Runs anomaly detection on compatible Suricata/network features.

The current anomaly-detection model uses Isolation Forest.

---

## 7. Threat Intelligence

## 7.1 Generic IP enrichment

```http
GET /threat-intelligence/ip/{ip_address}
```

Enriches an IP address using the Threat Intelligence service.

---

## 7.2 Analyze indicator

```http
POST /threat-intelligence/analyze
```

Analyzes a supported indicator using Threat Intelligence services.

---

## 7.3 Incident enrichment

```http
GET /threat-intelligence/incident/{incident_id}
```

Returns Threat Intelligence enrichment associated with an incident.

---

## 7.4 VirusTotal

### IP address

```http
GET /threat-intelligence/virustotal/ip/{ip_address}
```

### Domain

```http
GET /threat-intelligence/virustotal/domain/{domain}
```

### URL

```http
POST /threat-intelligence/virustotal/url
```

### File hash

```http
GET /threat-intelligence/virustotal/hash/{file_hash}
```

---

## 7.5 AlienVault OTX

### IP address

```http
GET /threat-intelligence/otx/ip/{ip_address}
```

### Domain

```http
GET /threat-intelligence/otx/domain/{domain}
```

### URL

```http
POST /threat-intelligence/otx/url
```

### File hash

```http
GET /threat-intelligence/otx/hash/{file_hash}
```

---

## 8. MITRE ATT&CK

### Get MITRE technique

```http
GET /mitre/technique/{technique_id}
```

Returns information for a MITRE ATT&CK technique.

Example:

```text
T1110
```

---

## 9. SOC Agents

### Analyze incident

```http
POST /agents/analyze/{incident_id}
```

Starts the LangGraph SOC workflow for an incident.

The workflow can include:

```text
Triage
-> Machine Learning
-> Threat Intelligence
-> Investigation
-> Human Review
-> Response
-> Report
```

---

### Resume interrupted workflow

```http
POST /agents/resume/{thread_id}
```

Resumes an interrupted Human-in-the-Loop workflow.

This route is intended for authorized administrative control.

---

## 10. SOAR

### List SOAR actions

```http
GET /soar
```

Returns SOAR actions.

---

### Get SOAR action

```http
GET /soar/{action_id}
```

Returns a specific SOAR action.

---

### Create SOAR action

```http
POST /soar
```

Creates a proposed SOAR action.

---

### Approve SOAR action

```http
POST /soar/{action_id}/approve
```

Approves a pending SOAR action.

---

### Reject SOAR action

```http
POST /soar/{action_id}/reject
```

Rejects a pending SOAR action.

---

### Execute SOAR action

```http
POST /soar/{action_id}/execute
```

Executes or simulates an approved SOAR action according to the configured execution mode.

The default prototype mode is:

```text
dry_run
```

---

### Get SOAR audit logs

```http
GET /soar/{action_id}/logs
```

Returns lifecycle and execution logs for a SOAR action.

---

## 11. Wazuh Ingestion

### Ingest Wazuh alert

```http
POST /wazuh/alerts
```

Receives security alerts from Wazuh.

This route is protected by the SOC ingestion API key.

Expected authentication header:

```text
X-SOC-Ingestion-Key
```

Real ingestion keys must never be included in documentation or source control.

---

## 12. Suricata Ingestion

### Ingest Suricata event

```http
POST /suricata/alerts
```

Receives Suricata EVE JSON security events.

This route is also protected by the machine-to-machine ingestion API key.

---

## 13. Analyst Assistant

### Ask the SOC assistant

```http
POST /analyst/ask
```

Provides a natural-language interface for SOC-oriented questions.

The assistant can use available cybersecurity context to help analysts investigate incidents and security concepts.

---

## 14. SOC Reports

### List reports

```http
GET /reports
```

Returns generated SOC reports.

---

### Get reports for an incident

```http
GET /reports/incident/{incident_id}
```

Returns reports linked to a specific incident.

---

### Get report

```http
GET /reports/{report_id}
```

Returns a specific SOC report.

---

## 15. Monitoring

### Application root

```http
GET /
```

Returns the application root response.

---

### Health check

```http
GET /health
```

Returns backend health status.

Validated endpoint:

```text
https://soc.local/health
```

---

### SOC metrics

```http
GET /metrics
```

Returns SOC metrics.

---

### Severity metrics

```http
GET /metrics/severity
```

Returns incident metrics grouped by severity.

---

### Dashboard metrics

```http
GET /metrics/dashboard
```

Returns metrics intended for SOC dashboard consumption.

---

### Prometheus metrics

```http
GET /prometheus
```

Exposes metrics in Prometheus-compatible format.

---

## 16. API Documentation Routes

FastAPI automatically exposes the following routes.

### OpenAPI schema

```http
GET /openapi.json
HEAD /openapi.json
```

---

### Swagger UI

```http
GET /docs
HEAD /docs
```

---

### Swagger OAuth redirect

```http
GET /docs/oauth2-redirect
HEAD /docs/oauth2-redirect
```

---

### ReDoc

```http
GET /redoc
HEAD /redoc
```

---

## 17. Authentication Model

The backend supports local JWT authentication and Keycloak/OpenID Connect integration.

Protected endpoints expect an access token in the standard Authorization header:

```text
Authorization: Bearer <access_token>
```

Never place real access tokens in:

- README files
- screenshots
- Git commits
- public issue trackers
- terminal transcripts intended for sharing

---

## 18. Role-Based Access Control

The application uses Role-Based Access Control.

Example roles include:

```text
analyst
admin
```

Sensitive operations such as Human-in-the-Loop workflow resume and SOAR administration are restricted according to backend authorization rules.

A `401 Unauthorized` response generally indicates missing or invalid authentication.

A `403 Forbidden` response generally indicates that the authenticated user does not have the required role or permission.

---

## 19. Machine-to-Machine Authentication

Security telemetry ingestion uses a dedicated API key.

Header:

```text
X-SOC-Ingestion-Key
```

This mechanism is separate from interactive analyst JWT authentication.

It is intended for trusted data sources such as:

```text
Wazuh
Suricata
```

The backend uses a constant-time comparison mechanism when validating the ingestion key.

---

## 20. HTTPS

The validated Docker prototype is exposed through Traefik using:

```text
https://soc.local
```

Example request:

```bash
curl -k https://soc.local/health
```

The `-k` flag is only appropriate for the local prototype when using an untrusted development certificate.

---

## 21. Error Handling

The API uses controlled HTTP errors.

Common responses include:

```text
200 OK
201 Created
204 No Content
400 Bad Request
401 Unauthorized
403 Forbidden
404 Not Found
422 Unprocessable Entity
429 Too Many Requests
500 Internal Server Error
503 Service Unavailable
```

The backend includes error sanitization to reduce exposure of internal implementation details and secrets.

Exact responses depend on the endpoint and request state.

---

## 22. Interactive API Testing

The recommended way to inspect exact request schemas is Swagger UI:

```text
https://soc.local/docs
```

Swagger automatically displays:

- request bodies
- query parameters
- path parameters
- response models
- validation requirements
- authentication requirements

This documentation should be preferred over manually guessing JSON payload structures.

---

## 23. Registered Backend Routes

The following application routes were directly enumerated from the running FastAPI backend:

```text
POST   /ml/predict
POST   /ml/suricata-anomaly

POST   /auth/register
POST   /auth/login
GET    /auth/me

POST   /alerts
GET    /alerts
GET    /alerts/{alert_id}
PUT    /alerts/{alert_id}
DELETE /alerts/{alert_id}

GET    /incidents
POST   /incidents
GET    /incidents/correlation/{correlation_id}
GET    /incidents/{incident_id}
PUT    /incidents/{incident_id}
DELETE /incidents/{incident_id}

GET    /ai-analysis
GET    /ai-analysis/incident/{incident_id}
GET    /ai-analysis/{analysis_id}
POST   /ai-analysis
PUT    /ai-analysis/{analysis_id}
DELETE /ai-analysis/{analysis_id}
POST   /ai-analysis/generate/{incident_id}

GET    /soar
GET    /soar/{action_id}/logs
GET    /soar/{action_id}
POST   /soar
POST   /soar/{action_id}/approve
POST   /soar/{action_id}/reject
POST   /soar/{action_id}/execute

GET    /threat-intelligence/ip/{ip_address}
POST   /threat-intelligence/analyze

GET    /threat-intelligence/virustotal/ip/{ip_address}
GET    /threat-intelligence/virustotal/domain/{domain}
POST   /threat-intelligence/virustotal/url
GET    /threat-intelligence/virustotal/hash/{file_hash}

GET    /threat-intelligence/otx/ip/{ip_address}
GET    /threat-intelligence/otx/domain/{domain}
POST   /threat-intelligence/otx/url
GET    /threat-intelligence/otx/hash/{file_hash}

GET    /threat-intelligence/incident/{incident_id}

GET    /mitre/technique/{technique_id}

POST   /agents/analyze/{incident_id}
POST   /agents/resume/{thread_id}

POST   /wazuh/alerts
POST   /suricata/alerts

GET    /metrics
GET    /metrics/severity
GET    /metrics/dashboard

POST   /analyst/ask

GET    /reports
GET    /reports/incident/{incident_id}
GET    /reports/{report_id}

GET    /
GET    /health

GET    /prometheus
```

FastAPI documentation routes are additionally available:

```text
GET/HEAD /openapi.json
GET/HEAD /docs
GET/HEAD /docs/oauth2-redirect
GET/HEAD /redoc
```

---

## 24. API Summary

The API can be conceptually grouped as:

```text
Authentication
      |
      v
Alerts / Incidents
      |
      +--------------------+
      |                    |
      v                    v
Machine Learning     Threat Intelligence
      |                    |
      +---------+----------+
                |
                v
          AI Investigation
                |
                v
          MITRE ATT&CK
                |
                v
        LangGraph Agents
                |
                v
        Human-in-the-Loop
                |
                v
              SOAR
                |
                v
             Reports
                |
                v
            Monitoring
```

The live OpenAPI schema remains the authoritative source for exact request and response models.