# AI-Powered SOC Analyst

AI-Powered SOC Analyst is a Security Operations Center (SOC) platform designed to centralize security alerts, detect and correlate incidents, enrich threats with external intelligence, and assist SOC analysts using artificial intelligence and automated response workflows.

The platform integrates **Wazuh**, **Suricata**, **FastAPI**, **PostgreSQL**, **Machine Learning**, **Threat Intelligence**, **RAG**, **Groq/Qwen**, **MITRE ATT&CK**, **LangGraph multi-agent workflows**, **Human-in-the-Loop (HITL)**, and **SOAR** capabilities.

---

## Main Objectives

The project aims to:

- Centralize security alerts from multiple sources.
- Convert security alerts into structured incidents.
- Correlate related incidents from different security sources.
- Detect attack patterns using Machine Learning.
- Enrich suspicious IP addresses using Threat Intelligence.
- Analyze incidents using an LLM and RAG knowledge base.
- Map detected attacks to MITRE ATT&CK techniques.
- Orchestrate SOC analysis using specialized AI agents.
- Require analyst approval for sensitive high-risk responses.
- Generate structured SOC reports.
- Propose and audit SOAR response actions.
- Provide safe response simulation using SOAR dry-run mode.

---

## Architecture

```text
                 +------------------+
                 |      Wazuh       |
                 +--------+---------+
                          |
                          v
+----------+      +-------+--------+
| Suricata | ---> |    FastAPI     |
+----------+      |    Backend     |
                  +-------+--------+
                          |
                          v
                  +-------+--------+
                  |   PostgreSQL   |
                  +-------+--------+
                          |
                          v
                +---------+----------+
                | Incident Correlation|
                +---------+----------+
                          |
                          v
                  +-------+--------+
                  | LangGraph SOC  |
                  |    Workflow    |
                  +-------+--------+
                          |
        +-----------------+-----------------+
        |                 |                 |
        v                 v                 v
   Machine Learning   Threat Intel.     RAG + LLM
                                           |
                                           v
                                     MITRE ATT&CK
                                           |
                                           v
                                  Human Review / HITL
                                           |
                                           v
                                        Response
                                           |
                          +----------------+---------------+
                          |                                |
                          v                                v
                     SOC Report                       SOAR Actions
                                                           |
                                                           v
                                                   Audit / Dry Run
```

---

## Multi-Agent SOC Workflow

The SOC workflow is orchestrated with LangGraph.

```text
START
  |
  v
Triage Agent
  |
  v
Machine Learning
  |
  v
Threat Intelligence
  |
  v
Investigation Agent
(RAG + LLM + MITRE ATT&CK)
  |
  +---- High / Critical ----> Human Review
  |                              |
  +------------------------------+
  |
  v
Response Agent
  |
  v
Report Agent
  |
  v
END
```

For high or critical incidents, the workflow can be interrupted until a SOC analyst approves or rejects the proposed response.

---

## Security Sources

### Wazuh

Wazuh is used for host-based security monitoring and alert generation.

Wazuh alerts can be forwarded to:

```text
POST /wazuh/alerts
```

### Suricata

Suricata provides network IDS/IPS detection.

EVE JSON alerts are forwarded to:

```text
POST /suricata/alerts
```

The integration has been tested with network scanning scenarios such as TCP SYN/Nmap scans.

---

## Incident Correlation

The platform correlates related incidents using contextual information such as:

- source IP
- destination IP
- hostname
- security source
- temporal context

Correlated incidents share a correlation identifier.

The platform also considers source diversity when calculating correlation confidence.

```text
GET /incidents/correlation/{correlation_id}
```

---

## Machine Learning

Machine Learning analysis is integrated into the SOC workflow.

Prediction endpoint:

```text
POST /ml/predict
```

ML results can be incorporated into the incident investigation and final SOC report when the required features are available.

---

## Threat Intelligence

Threat Intelligence enrichment is performed using AbuseIPDB.

The service can enrich suspicious IP addresses with information such as:

- abuse confidence score
- country
- ISP
- domain
- usage type
- number of reports

Endpoints:

```text
GET  /threat-intelligence/ip/{ip_address}
POST /threat-intelligence/analyze
GET  /threat-intelligence/incident/{incident_id}
```

---

## AI Analysis

The AI analysis layer uses an LLM through the Groq API.

Default model:

```text
qwen/qwen3.6-27b
```

The AI analysis produces structured information including:

- summary
- risk level
- explanation
- recommendation
- MITRE ATT&CK technique

Endpoints:

```text
GET    /ai-analysis
GET    /ai-analysis/incident/{incident_id}
GET    /ai-analysis/{analysis_id}
POST   /ai-analysis
PUT    /ai-analysis/{analysis_id}
DELETE /ai-analysis/{analysis_id}

POST /ai-analysis/generate/{incident_id}
```

The LLM service also includes handling for API rate limits and malformed model responses.

---

## RAG

Retrieval-Augmented Generation provides additional cybersecurity context to the investigation agent.

Relevant security knowledge can be retrieved and included in the LLM investigation context before the final analysis is generated.

RAG sources used during an investigation can also be stored in the resulting analysis/report.

---

## MITRE ATT&CK

AI-proposed MITRE ATT&CK techniques are validated by the MITRE service.

Endpoint:

```text
GET /mitre/technique/{technique_id}
```

Example:

```text
T1046 - Network Service Discovery
```

---

## Human-in-the-Loop

High-risk or critical incidents can require explicit SOC analyst validation before the workflow continues.

Analysis:

```text
POST /agents/analyze/{incident_id}
```

Resume an interrupted workflow:

```text
POST /agents/resume/{thread_id}
```

This allows an analyst to approve or reject a proposed response.

---

## SOAR

The SOAR module manages response actions.

Supported API operations include:

```text
GET  /soar
GET  /soar/{action_id}
POST /soar

POST /soar/{action_id}/approve
POST /soar/{action_id}/reject
POST /soar/{action_id}/execute

GET /soar/{action_id}/logs
```

SOAR actions include concepts such as:

- security ticket creation
- IP blocking proposals
- endpoint isolation proposals

### Safe Execution

The default configuration is:

```env
SOAR_EXECUTION_MODE=dry_run
SOAR_ENABLE_BLOCK_IP=false
SOAR_ENABLE_ISOLATE_ENDPOINT=false
```

Therefore potentially disruptive response actions are not executed against real infrastructure by default.

The SOAR audit trail records action lifecycle events and execution/simulation results.

---

## SOC Reports

The Report Agent generates structured SOC reports containing investigation results such as:

- incident information
- AI analysis
- risk level
- ML results
- MITRE ATT&CK mapping
- RAG sources
- correlation context
- human review status
- response status
- agent execution trace

Endpoints:

```text
GET /reports
GET /reports/incident/{incident_id}
GET /reports/{report_id}
```

---

## REST API

### Authentication

```text
POST /auth/register
POST /auth/login
```

### Alerts

```text
POST   /alerts
GET    /alerts
GET    /alerts/{alert_id}
PUT    /alerts/{alert_id}
DELETE /alerts/{alert_id}
```

### Incidents

```text
GET    /incidents
POST   /incidents
GET    /incidents/correlation/{correlation_id}
GET    /incidents/{incident_id}
PUT    /incidents/{incident_id}
DELETE /incidents/{incident_id}
```

### AI Agents

```text
POST /agents/analyze/{incident_id}
POST /agents/resume/{thread_id}
```

### Monitoring

```text
GET /
GET /health
```

Interactive API documentation is available through Swagger UI:

```text
http://127.0.0.1:8000/docs
```

---

## Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- Pydantic
- Alembic
- PostgreSQL

### Artificial Intelligence

- LangGraph
- Groq API
- Qwen
- Retrieval-Augmented Generation (RAG)

### Cybersecurity

- Wazuh
- Suricata
- AbuseIPDB
- MITRE ATT&CK
- SOAR
- Human-in-the-Loop

### Machine Learning

- Scikit-learn / project ML pipeline
- Network attack classification

### Infrastructure

- Linux
- Docker
- Git / GitHub

---

## Project Structure

```text
ai-powered-soc-analyst/
|
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   ├── api/
│   │   ├── core/
│   │   ├── database/
│   │   ├── ml/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── utils/
│   │
│   ├── data/
│   ├── migrations/
│   ├── tests/
│   ├── .env.example
│   └── requirements.txt
│
├── frontend/
├── data/
├── docker/
├── docs/
├── scripts/
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Environment Configuration

Create the backend environment file from the provided example:

```bash
cd backend
cp .env.example .env
```

Configure the required values in `.env`.

Main variables:

```env
SECRET_KEY=your_secret_key

DATABASE_URL=postgresql://soc_admin:your_password@localhost:5432/soc_db

GROQ_API_KEY=your_groq_api_key
LLM_MODEL=qwen/qwen3.6-27b
LLM_BASE_URL=https://api.groq.com/openai/v1

ABUSEIPDB_API_KEY=your_abuseipdb_api_key

SOAR_EXECUTION_MODE=dry_run
SOAR_ENABLE_BLOCK_IP=false
SOAR_ENABLE_ISOLATE_ENDPOINT=false
```

Never commit the real `.env` file or API keys to Git.

---

## Backend Installation

Create and activate a virtual environment:

```bash
cd backend

python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Configure `.env`, then apply database migrations:

```bash
alembic upgrade head
```

---

## Run the Backend

Start FastAPI with:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

Health endpoint:

```text
GET /health
```

---

## Tests

Run the backend test suite with:

```bash
cd backend
source venv/bin/activate
python -m pytest -v
```

The smoke tests verify:

- FastAPI application startup
- OpenAPI availability
- registration of core SOC API routes

---

## Demonstrated End-to-End Flow

The platform supports the following complete SOC flow:

```text
Security Event
     |
     v
Wazuh / Suricata
     |
     v
FastAPI ingestion
     |
     v
Incident creation
     |
     v
Correlation
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
RAG + LLM Investigation
     |
     v
MITRE ATT&CK
     |
     v
Human Review (when required)
     |
     v
Response
     |
     v
SOC Report
     |
     v
SOAR Action / Dry Run
     |
     v
Audit Trail
```

This architecture keeps the SOC analyst in control of sensitive response actions while using AI and automation to accelerate investigation and response.

---

## Security Notes

- API keys and secrets are stored in `.env`.
- `.env` must not be committed to Git.
- `.env.example` contains only example values.
- SOAR defaults to `dry_run`.
- IP blocking and endpoint isolation are disabled by default.
- High-risk response workflows can require human approval.

---

## Project Status

The backend currently includes the main SOC analysis pipeline:

- Alert and incident management
- Wazuh integration
- Suricata integration
- Incident correlation
- Machine Learning integration
- Threat Intelligence enrichment
- RAG-based investigation
- LLM-based analysis
- MITRE ATT&CK validation
- LangGraph multi-agent orchestration
- Human-in-the-Loop
- SOC report generation
- SOAR response workflow
- SOAR audit logging
- Backend smoke tests

The frontend dashboard is maintained as a separate project component.

---

## Academic Context

This project was developed as a Final Year Project (PFE) focused on applying artificial intelligence, cybersecurity monitoring, threat intelligence, automation, and human-supervised response to modern Security Operations Center workflows.
