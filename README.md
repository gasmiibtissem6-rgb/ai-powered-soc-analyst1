# AI-Powered SOC Analyst

AI-Powered SOC Analyst is a Security Operations Center (SOC) platform designed to centralize security alerts, detect and correlate incidents, enrich threats with external intelligence, and assist SOC analysts using artificial intelligence, machine learning, retrieval-augmented generation, and automated response workflows.

The platform integrates **Wazuh**, **Suricata**, **FastAPI**, **PostgreSQL**, **Redis**, **Qdrant**, **Machine Learning**, **Threat Intelligence**, **LlamaIndex RAG**, **Groq**, **MITRE ATT&CK**, **LangGraph multi-agent workflows**, **Human-in-the-Loop (HITL)**, **SOAR**, **HashiCorp Vault**, **Keycloak**, **Traefik**, **Prometheus**, and **Grafana**.

---

## Main Objectives

The project aims to:

- Centralize security alerts from multiple sources.
- Normalize security events and convert them into structured incidents.
- Correlate related incidents across security sources.
- Detect known attack patterns using supervised Machine Learning.
- Detect unusual network behavior using anomaly detection.
- Enrich indicators of compromise using external Threat Intelligence providers.
- Analyze incidents using an LLM and a cybersecurity RAG knowledge base.
- Map detected behavior to MITRE ATT&CK techniques.
- Orchestrate SOC investigations using specialized AI agents.
- Require human approval for sensitive high-risk response workflows.
- Generate structured SOC investigation reports.
- Propose, audit, approve, reject, and execute SOAR response actions.
- Provide safe response simulation through SOAR dry-run mode.
- Expose SOC operational metrics through Prometheus and Grafana.
- Protect APIs and secrets using authentication, RBAC, Vault, and HTTPS.

---

## Architecture

```text
        +-------------+           +-------------+
        |    Wazuh    |           |  Suricata   |
        +------+------+           +------+------+
               |                         |
               +------------+------------+
                            |
                            v
                   +--------+--------+
                   | FastAPI Backend |
                   +--------+--------+
                            |
             +--------------+--------------+
             |                             |
             v                             v
      +-------------+                +-------------+
      | PostgreSQL  |                |    Redis    |
      +------+------+                +-------------+
             |
             v
     +-------+---------+
     | Alert / Incident|
     |   Correlation   |
     +-------+---------+
             |
             v
     +-------+---------+
     | LangGraph SOC   |
     |    Workflow     |
     +-------+---------+
             |
     +-------+--------------------+------------------+
     |                            |                  |
     v                            v                  v
+------------+            +---------------+    +-----------+
| Hybrid ML  |            | Threat Intel. |    | RAG + LLM |
+------------+            +---------------+    +-----+-----+
 RF / XGBoost                                     |
 Isolation Forest                                 v
                                               Qdrant
                                                  |
                                                  v
                                           MITRE ATT&CK
                                                  |
                                                  v
                                           Human Review
                                              / HITL
                                                  |
                                                  v
                                               Response
                                                  |
                                    +-------------+-------------+
                                    |                           |
                                    v                           v
                               SOC Report                  SOAR Actions
                                                               |
                                                               v
                                                        Audit / Dry Run
```

Infrastructure and security services include:

```text
Traefik -> HTTPS reverse proxy
Keycloak -> OIDC authentication
Vault -> secret management
Prometheus -> metrics collection
Grafana -> monitoring dashboards
Qdrant -> vector database for RAG
Redis -> Threat Intelligence cache
PostgreSQL -> persistent SOC data
```

---

## Multi-Agent SOC Workflow

The SOC workflow is orchestrated with **LangGraph**.

```text
START
  |
  v
Triage Agent
  |
  v
Machine Learning Agent
  |
  v
Threat Intelligence Agent
  |
  v
Investigation Agent
(RAG + LLM + MITRE ATT&CK)
  |
  +---- High / Critical ----> Human Review / HITL
  |                                  |
  |                            Approve / Reject
  |                                  |
  +----------------------------------+
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

For high or critical incidents, the workflow can be interrupted using LangGraph's Human-in-the-Loop mechanism.

An authorized administrator can then approve or reject the workflow before the response phase continues.

---

## Security Sources

### Wazuh

Wazuh provides host-based security monitoring and alert generation.

Wazuh alerts can be forwarded to:

```text
POST /wazuh/alerts
```

The ingestion endpoint is protected by a machine-to-machine ingestion API key.

The prototype has been validated with real Wazuh alerts generated by a monitored Linux endpoint and indexed through the Wazuh stack.

### Suricata

Suricata provides network IDS/IPS monitoring using EVE JSON events.

Events can be forwarded to:

```text
POST /suricata/alerts
```

Suricata events can also provide network-flow information to the Machine Learning pipeline.

The ingestion endpoint is protected by the same machine-to-machine authentication mechanism.

---

## Incident Correlation

The platform correlates related incidents using contextual information such as:

- source IP
- destination IP
- hostname
- security source
- temporal context
- correlation identifiers
- source diversity

Correlated incidents can be retrieved through:

```text
GET /incidents/correlation/{correlation_id}
```

Correlation information is also made available to the AI investigation workflow.

---

## Machine Learning

The platform implements a **hybrid Machine Learning pipeline**.

The current prototype combines:

- **Random Forest** — supervised network attack classification
- **XGBoost** — supervised network attack classification
- **Isolation Forest** — unsupervised anomaly detection

Prediction endpoints:

```text
POST /ml/predict
POST /ml/suricata-anomaly
```

The supervised models can classify network traffic according to learned classes, while Isolation Forest detects statistically unusual behavior.

The SOC workflow preserves the individual results of the three models instead of relying only on a single global prediction.

For example, when Random Forest and XGBoost classify traffic as `BENIGN` while Isolation Forest detects an `ANOMALY`, the LLM receives both signals and must explicitly reason about the disagreement.

An anomaly increases suspicion but does not automatically prove malicious activity.

The ML pipeline has been developed using cybersecurity datasets including:

- CICIDS2017
- CSE-CIC-IDS2018
- UNSW-NB15

---

## Threat Intelligence

Threat Intelligence enrichment supports multiple providers.

### Active providers

The prototype has been validated with:

- **AbuseIPDB**
- **VirusTotal**
- **AlienVault OTX**

The platform supports enrichment for indicators such as:

- IP addresses
- domains
- URLs
- file hashes

Available endpoints include:

```text
GET  /threat-intelligence/ip/{ip_address}
POST /threat-intelligence/analyze
GET  /threat-intelligence/incident/{incident_id}

GET  /threat-intelligence/virustotal/ip/{ip_address}
GET  /threat-intelligence/virustotal/domain/{domain}
GET  /threat-intelligence/virustotal/hash/{file_hash}
POST /threat-intelligence/virustotal/url

GET  /threat-intelligence/otx/ip/{ip_address}
GET  /threat-intelligence/otx/domain/{domain}
GET  /threat-intelligence/otx/hash/{file_hash}
POST /threat-intelligence/otx/url
```

### Redis Cache

Threat Intelligence enrichment is cached using **Redis** for supported IOC types including IP addresses, domains, URLs, and file hashes.

The cache:

- reduces repeated calls to external providers,
- stores normalized enrichment results,
- uses a configurable TTL,
- improves investigation latency.

The current implementation uses cache keys such as:

```text
soc:ti:ip:{ip_address}
```

### MISP

MISP support is implemented as an optional Threat Intelligence provider.

Supported IOC types include:

- IP
- domain
- URL
- file hash

If no MISP instance is configured, the provider returns:

```text
status: not_configured
```

and the SOC workflow continues normally.

**MISP is integrated and validated in the current prototype environment.**

The SOC backend can query MISP for IP addresses, domains, URLs, and file hashes. Unlike Internet-based Threat Intelligence providers, MISP may also be queried for private, reserved, lab, or documentation addresses because it acts as an internal Threat Intelligence platform.

---

## AI Analysis

The AI analysis layer communicates with an OpenAI-compatible LLM API through **Groq**.

Current prototype model:

```text
openai/gpt-oss-120b
```

Base API:

```text
https://api.groq.com/openai/v1
```

The AI investigation produces structured information including:

- summary
- risk level
- explanation
- recommendation
- MITRE ATT&CK technique

Endpoints:

```text
GET    /ai-analysis
POST   /ai-analysis

GET    /ai-analysis/incident/{incident_id}
GET    /ai-analysis/{analysis_id}
PUT    /ai-analysis/{analysis_id}
DELETE /ai-analysis/{analysis_id}

POST /ai-analysis/generate/{incident_id}
```

The LLM receives evidence from multiple SOC components when available, including:

- incident information
- Machine Learning results
- Threat Intelligence
- RAG evidence
- correlation information
- security-source evidence

The prompt explicitly instructs the LLM to reason about disagreement between supervised classification and anomaly detection rather than treating any individual ML result as definitive proof.

> The original project specification considered Kimi K3. The current prototype uses Groq with `openai/gpt-oss-120b` because the configured Moonshot/Kimi service was not available within the prototype's API quota.

---

## Retrieval-Augmented Generation (RAG)

Retrieval-Augmented Generation provides cybersecurity knowledge to the Investigation Agent.

The implementation uses:

- **LlamaIndex**
- **Qdrant**
- **Hugging Face embeddings**
- `sentence-transformers/all-MiniLM-L6-v2`

The cybersecurity knowledge base contains material such as:

- MITRE ATT&CK knowledge
- SOC playbooks
- incident response guidance
- security runbooks

Documents are chunked, embedded, and stored in Qdrant.

The current Qdrant collection is:

```text
soc_knowledge
```

Relevant security context is retrieved semantically and included in the LLM investigation context.

RAG sources can also be preserved in SOC investigation reports.

The RAG layer includes protections intended to reduce prompt-injection risks from retrieved content.

---

## MITRE ATT&CK

AI-proposed MITRE ATT&CK techniques are validated by the MITRE service before being used as validated mappings.

Endpoint:

```text
GET /mitre/technique/{technique_id}
```

Example:

```text
T1110 - Brute Force
```

MITRE information is also incorporated into the investigation and reporting workflow.

---

## Human-in-the-Loop

High-risk or critical incidents can require explicit human validation.

Start analysis:

```text
POST /agents/analyze/{incident_id}
```

Resume an interrupted workflow:

```text
POST /agents/resume/{thread_id}
```

The resume operation is restricted to authorized administrative users.

The Human-in-the-Loop mechanism allows an analyst or administrator to approve or reject the proposed response before the workflow continues.

This prevents high-risk automated actions from bypassing human supervision.

---

## SOAR

The prototype implements an **internal SOAR module**.

Supported operations include:

```text
GET  /soar
POST /soar
GET  /soar/{action_id}

POST /soar/{action_id}/approve
POST /soar/{action_id}/reject
POST /soar/{action_id}/execute

GET /soar/{action_id}/logs
```

Supported response concepts include:

- security ticket creation
- IP blocking
- endpoint isolation
- user disabling
- notifications

### Human Approval

Sensitive SOAR actions can require approval before execution.

The lifecycle supports:

```text
Create
  |
  v
Pending Approval
  |
  +---- Reject
  |
  +---- Approve
          |
          v
       Execute
          |
          v
       Audit Log
```

### Safe Execution

The prototype defaults to safe execution settings:

```env
SOAR_EXECUTION_MODE=dry_run
SOAR_ENABLE_BLOCK_IP=false
SOAR_ENABLE_ISOLATE_ENDPOINT=false
SOAR_ENABLE_DISABLE_USER=false
SOAR_ENABLE_SEND_NOTIFICATION=false
```

Potentially disruptive actions are therefore not executed against real infrastructure by default.

### Shuffle

The backend includes an optional integration with **Shuffle SOAR** through webhook-based workflows.

Shuffle integration is configurable through `SHUFFLE_*` environment variables. The internal FastAPI SOAR remains the primary response engine and supports approval, safety controls, dry-run execution, and audit logging.

---

## SOC Reports

The Report Agent generates structured SOC reports containing investigation evidence such as:

- incident information
- AI analysis
- risk level
- Machine Learning results
- MITRE ATT&CK mapping
- RAG sources
- Threat Intelligence
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

## Authentication and Authorization

The backend supports authentication and Role-Based Access Control (RBAC).

Local authentication uses JWT tokens.

Endpoints:

```text
POST /auth/register
POST /auth/login
GET  /auth/me
```

Protected SOC endpoints require authenticated users with appropriate roles.

The prototype also integrates **Keycloak** for OpenID Connect authentication.

Keycloak configuration includes:

```text
Realm: soc
Client: soc-backend
```

The Keycloak integration validates tokens using the provider's JWKS keys.

For frontend applications, Authorization Code Flow with PKCE is the intended authentication approach.

---

## Secret Management

Sensitive backend configuration can be retrieved through **HashiCorp Vault**.

The prototype uses the Vault KV v2 secret engine.

Configured path:

```text
secret/soc-backend
```

The validated Vault configuration contains the required backend secrets, including:

```text
SECRET_KEY
SOC_INGESTION_API_KEY
GROQ_API_KEY
ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
OTX_API_KEY
MISP_API_KEY
```

The application Secret Manager attempts to obtain sensitive values from Vault and can fall back to application configuration when appropriate.

**Important:** The current Docker Compose environment uses persistent Vault file storage with a Docker volume and Shamir sealing.

Vault is initialized with a dedicated backend policy. The FastAPI backend uses a renewable read-only token and cannot modify stored secrets.

After a complete Vault restart, the current prototype requires a manual unseal operation before the backend can access Vault secrets.

For a production deployment, Vault should use an appropriate production-grade seal and operational security configuration.



Never commit real API keys, Vault tokens, passwords, JWTs, or `.env` files to Git.

---

## HTTPS and Reverse Proxy

**Traefik v3.6** is used as the reverse proxy for the prototype.

The primary backend URL is:

```text
https://soc.local
```

HTTP traffic is redirected to HTTPS.

Validated endpoints include:

```text
https://soc.local/health
https://soc.local/docs
https://soc.local/openapi.json
```

Local development certificates are not committed to Git.

---

## Monitoring

The platform exposes operational metrics for Prometheus.

Endpoints include:

```text
GET /metrics
GET /metrics/dashboard
GET /metrics/severity
```

The infrastructure includes:

- **Prometheus** for metrics collection
- **Grafana** for dashboard visualization

SOC metrics include information related to:

- total incidents
- incident severity distribution
- MTTD
- MTTR
- workflow activity

---

## REST API

The FastAPI application exposes **45 OpenAPI paths** in the current prototype.

### Authentication

```text
POST /auth/register
POST /auth/login
GET  /auth/me
```

### Alerts

```text
GET    /alerts
POST   /alerts
GET    /alerts/{alert_id}
PUT    /alerts/{alert_id}
DELETE /alerts/{alert_id}
```

### Incidents

```text
GET    /incidents
POST   /incidents
GET    /incidents/{incident_id}
PUT    /incidents/{incident_id}
DELETE /incidents/{incident_id}

GET /incidents/correlation/{correlation_id}
```

### AI Agents

```text
POST /agents/analyze/{incident_id}
POST /agents/resume/{thread_id}
```

### Machine Learning

```text
POST /ml/predict
POST /ml/suricata-anomaly
```

### Monitoring

```text
GET /
GET /health
GET /metrics
GET /metrics/dashboard
GET /metrics/severity
```

Interactive API documentation:

```text
https://soc.local/docs
```

OpenAPI schema:

```text
https://soc.local/openapi.json
```

---

## Technology Stack

### Backend

- Python 3.13
- FastAPI
- SQLAlchemy
- Pydantic
- Alembic
- PostgreSQL 16

### Artificial Intelligence

- LangGraph
- Groq OpenAI-compatible API
- `openai/gpt-oss-120b`
- LlamaIndex
- Retrieval-Augmented Generation (RAG)
- Hugging Face sentence-transformer embeddings
- Qdrant

### Machine Learning

- Scikit-learn
- XGBoost
- PyTorch CPU runtime
- Random Forest
- XGBoost classifier
- Isolation Forest

### Cybersecurity

- Wazuh
- Suricata
- MITRE ATT&CK
- AbuseIPDB
- VirusTotal
- AlienVault OTX
- Optional MISP integration
- Internal SOAR
- Human-in-the-Loop

### Security

- JWT
- RBAC
- Keycloak / OpenID Connect
- HashiCorp Vault
- Machine-to-machine ingestion API key
- HTTPS / TLS
- Traefik reverse proxy

### Data and Infrastructure

- PostgreSQL
- Redis
- Qdrant
- Docker Compose
- Prometheus
- Grafana
- Traefik
- Vault
- Keycloak
- Linux
- Git / GitHub
- GitHub Actions

---

## Docker Compose Services

The prototype Docker Compose stack includes:

```text
soc-backend
soc-postgres
soc-redis
soc-qdrant
soc-vault
soc-keycloak
soc-traefik
soc-prometheus
soc-grafana
```

Check service status with:

```bash
docker compose ps
```

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
│   ├── Dockerfile
│   └── requirements.txt
│
├── data/
├── docs/
├── infrastructure/
├── monitoring/
├── docker-compose.yml
└── README.md
```

---

## Environment Configuration

Create the backend environment file from the provided example:

```bash
cd backend
cp .env.example .env
```

Never place real credentials in `.env.example`.

Example development configuration:

```env
# Authentication
SECRET_KEY=change_me_with_a_secure_random_secret
SOC_INGESTION_API_KEY=change_me_with_a_secure_ingestion_key

# Database / Cache / Vector Store
DATABASE_URL=postgresql://soc_admin:your_password@localhost:5432/soc_db
REDIS_URL=redis://localhost:6379/0
QDRANT_URL=http://localhost:6333

# LLM
GROQ_API_KEY=your_groq_api_key_here
LLM_MODEL=openai/gpt-oss-120b
LLM_BASE_URL=https://api.groq.com/openai/v1

# Threat Intelligence
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
OTX_API_KEY=your_otx_api_key_here

# Optional MISP
MISP_URL=
MISP_API_KEY=
MISP_VERIFY_SSL=true

# SOAR
SOAR_EXECUTION_MODE=dry_run
SOAR_ENABLE_BLOCK_IP=false
SOAR_ENABLE_ISOLATE_ENDPOINT=false
SOAR_ENABLE_DISABLE_USER=false
SOAR_ENABLE_SEND_NOTIFICATION=false

# Vault
VAULT_ADDR=
VAULT_TOKEN=
VAULT_MOUNT_POINT=secret
VAULT_SECRET_PATH=soc-backend
```

The Docker Compose configuration overrides several service URLs so containers communicate through the Docker network.

---

## Backend Installation

The authoritative container runtime uses **Python 3.13**.

For local development:

```bash
cd backend

python3.13 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Apply database migrations:

```bash
alembic upgrade head
```

### Docker

The recommended prototype environment uses Docker Compose:

```bash
docker compose up -d --build
```

Check the services:

```bash
docker compose ps
```

---

## Run the Backend

For direct local development:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

For the validated Docker/Traefik environment:

```text
https://soc.local
```

Swagger UI:

```text
https://soc.local/docs
```

Health endpoint:

```text
GET /health
```

---

## Tests

Run the backend test suite inside the authoritative Python 3.13 Docker environment:

```bash
docker exec -w /app soc-backend python -m pytest -q
```

Current validated result:

```text
69 passed
```

The test suite covers components including:

- FastAPI startup
- API routes
- authentication and RBAC
- ingestion security
- alerts and incidents
- correlation
- Machine Learning adapters
- operational incident timestamps
- metrics
- SOAR services and execution
- Vault integration behavior
- security controls

SOAR-specific tests can be executed with:

```bash
docker exec -w /app soc-backend \
  python -m pytest -q \
  tests/test_soar_service.py \
  tests/test_soar_executor.py
```

Validated result:

```text
7 passed
```

---

## Demonstrated End-to-End SOC Flow

A representative end-to-end workflow has been validated through the backend.

```text
Security Event
     |
     v
Wazuh / Suricata
     |
     v
Authenticated FastAPI Ingestion
     |
     v
Normalization
     |
     v
Incident Creation
     |
     v
Correlation
     |
     v
Triage Agent
     |
     v
Hybrid Machine Learning
(Random Forest + XGBoost + Isolation Forest)
     |
     v
Threat Intelligence
     |
     v
RAG Retrieval
     |
     v
LLM Investigation
     |
     v
MITRE ATT&CK Validation
     |
     v
Human Review / HITL
     |
     v
Response Agent
     |
     v
SOC Report
     |
     v
SOAR Action
     |
     v
Audit Trail
```

A representative hybrid ML scenario demonstrated that the workflow can preserve conflicting evidence:

```text
Random Forest    -> BENIGN
XGBoost          -> BENIGN
Isolation Forest -> ANOMALY
```

The Investigation Agent used the full ML evidence and explicitly reasoned about the disagreement rather than ignoring the anomaly.

The high-risk workflow paused for Human Review and successfully continued after authorized approval through:

```text
Triage
-> Machine Learning
-> Threat Intelligence
-> Investigation
-> Human Review
-> Response
-> Report
```

The resulting AI analysis, SOC report, and SOAR action were persisted.

This validation demonstrates the integration of the main SOC pipeline. It does **not** imply that every attack type, dataset, security source, or response action has been tested end-to-end.

---

## Security Notes

The prototype includes multiple security controls:

- JWT authentication
- Role-Based Access Control (RBAC)
- Keycloak / OIDC integration
- HTTPS through Traefik
- machine-to-machine authentication for Wazuh and Suricata ingestion
- HashiCorp Vault secret management
- constant-time comparison for ingestion API keys
- restricted CORS origins
- sanitized API error handling
- prompt-injection protections for RAG
- Human-in-the-Loop approval
- SOAR dry-run mode
- audit logging

Sensitive values must never be committed to Git.

The following should remain excluded from source control:

```text
.env
API keys
passwords
Vault tokens
JWTs
TLS private keys
local certificates where appropriate
```

The current Vault and Keycloak containers use development-oriented modes for the prototype. They require production hardening before deployment in a real SOC environment.

---

## CI/CD

Backend tests are integrated with **GitHub Actions**.

The CI environment uses Python 3.13 and executes the backend automated test suite on repository changes.

This helps detect regressions before changes are accepted into the main branch.

---

## Prototype Limitations

The current prototype intentionally has several limitations:

- MISP support is implemented but no live MISP instance is configured.
- Shuffle is not integrated into the main prototype; the internal SOAR module is used instead.
- Vault currently runs in development mode.
- Keycloak currently runs in development mode.
- Destructive SOAR operations are disabled by default.
- Kubernetes/K3s deployment is considered future work.
- Commercial EDR integration is outside the current prototype scope.
- Full cloud-provider integration is outside the current prototype scope.
- Large-scale production load testing is outside the current scope.
- Not every attack category or security-source type has been validated end-to-end.

These limitations distinguish implemented prototype capabilities from planned production extensions.

---

## Project Status

The backend prototype currently includes:

- Alert and incident management
- Wazuh ingestion
- Suricata ingestion
- machine-to-machine ingestion authentication
- incident correlation and deduplication
- risk assessment
- Random Forest classification
- XGBoost classification
- Isolation Forest anomaly detection
- hybrid ML evidence processing
- AbuseIPDB Threat Intelligence
- VirusTotal Threat Intelligence
- AlienVault OTX Threat Intelligence
- optional MISP provider support
- Redis Threat Intelligence caching
- LlamaIndex RAG
- Qdrant vector storage
- LLM-based incident investigation
- MITRE ATT&CK validation
- LangGraph multi-agent orchestration
- Human-in-the-Loop
- SOC report generation
- internal SOAR workflows
- SOAR approval and audit logging
- PostgreSQL persistence
- JWT and RBAC
- Keycloak / OIDC
- HashiCorp Vault
- Traefik HTTPS
- Prometheus metrics
- Grafana dashboards
- Docker Compose infrastructure
- GitHub Actions CI
- Swagger / OpenAPI documentation
- automated backend tests

The frontend dashboard is maintained as a separate project component.

---

## Academic Context

This project was developed as a Final Year Project (PFE) focused on applying artificial intelligence, Machine Learning, cybersecurity monitoring, Threat Intelligence, Retrieval-Augmented Generation, multi-agent orchestration, automation, and human-supervised response to modern Security Operations Center workflows.

The prototype emphasizes a hybrid SOC architecture in which AI and automation assist analysts while sensitive response decisions remain under human control.