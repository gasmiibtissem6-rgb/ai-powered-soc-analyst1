# AI-Powered SOC Analyst — Technical Architecture

## 1. Overview

AI-Powered SOC Analyst is a modular Security Operations Center platform designed to centralize security events, correlate incidents, enrich indicators with Threat Intelligence, apply Machine Learning and AI-assisted investigation, and orchestrate controlled response actions.

The architecture combines traditional cybersecurity monitoring with:

- Security event ingestion
- Incident correlation
- Hybrid Machine Learning
- Threat Intelligence
- Retrieval-Augmented Generation (RAG)
- Large Language Model (LLM) analysis
- MITRE ATT&CK mapping
- LangGraph multi-agent orchestration
- Human-in-the-Loop (HITL)
- SOAR response workflows
- Centralized secret management
- Authentication and authorization
- Monitoring and observability

The prototype is primarily deployed using Docker Compose.

---

## 2. High-Level Architecture

```text
                  SECURITY SOURCES
              +----------------------+
              |                      |
              v                      v
        +-----------+          +-----------+
        |   Wazuh   |          | Suricata  |
        +-----+-----+          +-----+-----+
              |                      |
              +----------+-----------+
                         |
                         v
                +--------+---------+
                | FastAPI Backend  |
                |   Python 3.13    |
                +--------+---------+
                         |
          +--------------+---------------+
          |                              |
          v                              v
   +-------------+                +-------------+
   | PostgreSQL  |                |    Redis    |
   | SOC Storage |                |  TI Cache   |
   +------+------+                +-------------+
          |
          v
 +--------+---------+
 | Alert / Incident |
 |   Processing     |
 +--------+---------+
          |
          v
 +--------+---------+
 | Correlation and  |
 |   Risk Scoring   |
 +--------+---------+
          |
          v
 +--------+---------+
 | LangGraph SOC    |
 |    Workflow      |
 +--------+---------+
          |
     +----+--------------------+------------------+
     |                         |                  |
     v                         v                  v
+----------+           +---------------+     +----------+
|Hybrid ML |           | Threat Intel. |     |   RAG    |
+----+-----+           +-------+-------+     +----+-----+
     |                         |                  |
     |                         |                  v
     |                         |              +--------+
     |                         |              | Qdrant |
     |                         |              +---+----+
     |                         |                  |
     +-------------------------+------------------+
                               |
                               v
                         +-----+-----+
                         | Groq LLM  |
                         +-----+-----+
                               |
                               v
                       +-------+--------+
                       | MITRE ATT&CK   |
                       |   Validation   |
                       +-------+--------+
                               |
                               v
                       +-------+--------+
                       | Human Review   |
                       |     HITL       |
                       +-------+--------+
                               |
                               v
                       +-------+--------+
                       | Response Agent |
                       +-------+--------+
                               |
                  +------------+------------+
                  |                         |
                  v                         v
            +-----------+             +-----------+
            |SOC Reports|             |   SOAR    |
            +-----------+             +-----+-----+
                                          |
                                          v
                                   +-------------+
                                   | Audit Trail |
                                   |  / Dry Run  |
                                   +-------------+
```

---

## 3. Backend Layer

The core backend is implemented using:

- Python 3.13
- FastAPI
- SQLAlchemy
- Pydantic
- Alembic
- PostgreSQL

FastAPI exposes REST endpoints for the major SOC components, including:

- Authentication
- Alerts
- Incidents
- Wazuh ingestion
- Suricata ingestion
- Threat Intelligence
- Machine Learning
- AI Analysis
- MITRE ATT&CK
- SOC Agents
- Human Review
- SOC Reports
- SOAR
- Monitoring

The API is documented automatically through OpenAPI.

Validated documentation endpoints:

```text
https://soc.local/docs
https://soc.local/openapi.json
```

---

## 4. Security Event Ingestion

### 4.1 Wazuh

Wazuh provides host-based security monitoring.

The prototype has been validated with real Wazuh alerts generated by a monitored Linux endpoint.

Wazuh alerts are sent to:

```text
POST /wazuh/alerts
```

The ingestion route is protected by a dedicated machine-to-machine API key.

### 4.2 Suricata

Suricata provides network IDS/IPS visibility through EVE JSON events.

Suricata events are sent to:

```text
POST /suricata/alerts
```

Network information extracted from Suricata events can also be provided to the Machine Learning pipeline.

The ingestion route is protected by the same machine-to-machine authentication mechanism.

---

## 5. Data Persistence

### PostgreSQL

PostgreSQL is the main persistent relational database.

It stores SOC information including:

- users
- alerts
- incidents
- AI analyses
- SOC reports
- SOAR actions
- audit information

Database schema changes are managed through Alembic migrations.

### Redis

Redis is used as a cache for Threat Intelligence enrichment.

Example cache key:

```text
soc:ti:ip:{ip_address}
```

The cache reduces unnecessary external API calls and improves repeated enrichment latency.

The current Threat Intelligence cache uses a TTL of approximately 15 minutes.

### Qdrant

Qdrant is the vector database used by the RAG subsystem.

The current collection is:

```text
soc_knowledge
```

It stores vector embeddings generated from the cybersecurity knowledge base.

---

## 6. Incident Processing and Correlation

Incoming security events are normalized before being transformed into SOC alerts and incidents.

The correlation layer uses contextual attributes such as:

- source IP
- destination IP
- hostname
- security source
- timestamps
- correlation identifiers
- source diversity

The objective is to reduce isolated alert processing and provide a more complete view of related security activity.

Correlation information is subsequently made available to the AI investigation workflow.

---

## 7. Hybrid Machine Learning Architecture

The Machine Learning layer combines supervised classification with unsupervised anomaly detection.

### Random Forest

Random Forest provides supervised network traffic classification.

### XGBoost

XGBoost provides a second supervised classification signal.

### Isolation Forest

Isolation Forest performs unsupervised anomaly detection.

The hybrid architecture can therefore produce evidence such as:

```text
Random Forest    -> BENIGN
XGBoost          -> BENIGN
Isolation Forest -> ANOMALY
```

This disagreement is preserved and provided to the AI investigation layer.

An anomaly is treated as additional evidence rather than automatic proof of an attack.

The LLM is instructed to reason about the complete ML evidence.

Datasets used in the Machine Learning work include:

- CICIDS2017
- CSE-CIC-IDS2018
- UNSW-NB15

---

## 8. Threat Intelligence Architecture

The Threat Intelligence subsystem enriches suspicious indicators using external providers.

### Validated Providers

The current prototype has live integration with:

- AbuseIPDB
- VirusTotal
- AlienVault OTX

These services provide reputation and contextual information about indicators such as:

- IP addresses
- domains
- URLs
- file hashes

### MISP

MISP support is implemented as an optional provider.

The service can process:

- IP addresses
- domains
- URLs
- file hashes

However, no live MISP instance is configured in the current prototype.

When MISP is unavailable, the provider returns a controlled `not_configured` result without interrupting the SOC workflow.

### Redis Caching

IP enrichment results can be cached in Redis.

The enrichment workflow follows the general pattern:

```text
IOC
 |
 v
Redis Cache
 |
 +---- HIT ----> Return Cached Intelligence
 |
 +---- MISS
        |
        v
Threat Intelligence Providers
        |
        v
Normalize Results
        |
        v
Store in Redis
        |
        v
Return Enrichment
```

---

## 9. RAG Architecture

The Retrieval-Augmented Generation subsystem provides cybersecurity knowledge to the AI Investigation Agent.

The implementation uses:

- LlamaIndex
- Qdrant
- Hugging Face embeddings
- `sentence-transformers/all-MiniLM-L6-v2`

The workflow is:

```text
Cybersecurity Documents
        |
        v
Document Loading
        |
        v
Sentence Splitting
        |
        v
Embedding Generation
        |
        v
Qdrant Vector Storage
        |
        v
Semantic Retrieval
        |
        v
Investigation Context
        |
        v
LLM
```

The knowledge base contains cybersecurity material including MITRE ATT&CK information, SOC playbooks, and incident-response guidance.

Retrieved content is treated as contextual evidence and is subject to prompt-injection protections.

---

## 10. LLM Analysis

The prototype uses the Groq OpenAI-compatible API.

Current model:

```text
openai/gpt-oss-120b
```

API base URL:

```text
https://api.groq.com/openai/v1
```

The LLM analyzes evidence from multiple components, including:

- incident details
- severity
- security source
- Machine Learning evidence
- Threat Intelligence
- RAG context
- correlation information

The structured output includes:

- summary
- risk level
- explanation
- recommendation
- MITRE ATT&CK technique

The original project specification considered Kimi K3.

During prototype implementation, Groq with `openai/gpt-oss-120b` was used because the configured Moonshot/Kimi API was unavailable within the available prototype quota.

---

## 11. MITRE ATT&CK Integration

MITRE ATT&CK provides a standardized representation of attacker tactics and techniques.

The AI can propose a MITRE technique based on investigation evidence.

The backend then validates the proposed technique before considering it a validated mapping.

Example:

```text
T1110 - Brute Force
```

MITRE information is incorporated into SOC analysis and reporting.

---

## 12. LangGraph Multi-Agent Architecture

LangGraph orchestrates the main SOC analysis workflow.

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
  |
  +------ High / Critical ------+
  |                             |
  |                             v
  |                       Human Review
  |                             |
  +-----------------------------+
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

Each stage contributes evidence to the shared workflow state.

This architecture separates responsibilities while maintaining a unified investigation context.

---

## 13. Human-in-the-Loop Architecture

Human-in-the-Loop is used to prevent sensitive decisions from being performed without analyst supervision.

High or critical workflows can be interrupted before the response phase.

```text
Investigation
     |
     v
Risk Evaluation
     |
     +---- Low / Medium ----> Continue
     |
     +---- High / Critical
              |
              v
         Pause Workflow
              |
              v
         Human Review
          /       \
     Approve     Reject
        |           |
        v           v
    Continue      Stop /
    Response      Controlled handling
```

The resume endpoint is restricted to authorized administrative users.

---

## 14. SOAR Architecture

The current prototype implements an internal SOAR service.

Supported action concepts include:

- create security ticket
- block IP
- isolate endpoint
- disable user
- send notification

The lifecycle is:

```text
Proposed Action
      |
      v
Pending Approval
      |
 +----+----+
 |         |
 v         v
Reject   Approve
           |
           v
        Execute
           |
           v
       Audit Log
```

The default mode is:

```text
dry_run
```

Destructive actions are disabled by default.

This allows response workflows to be demonstrated without modifying real infrastructure.

### Shuffle

Shuffle was evaluated as an external SOAR option but is not integrated into the main prototype stack.

The validated prototype uses the internal SOAR implementation.

---

## 15. Authentication and Authorization

The platform supports two authentication mechanisms.

### Local Authentication

Local users authenticate using JWT tokens.

Role-Based Access Control restricts sensitive endpoints according to user role.

Example roles include:

```text
analyst
admin
```

### Keycloak

Keycloak provides OpenID Connect support.

Prototype configuration:

```text
Realm: soc
Client: soc-backend
```

Keycloak access tokens are validated using JWKS.

For a frontend application, Authorization Code Flow with PKCE is the intended authentication approach.

---

## 16. Secret Management

HashiCorp Vault is used as the primary secret-management mechanism in the prototype.

The backend Secret Manager attempts to retrieve sensitive values from Vault and can fall back to application configuration when appropriate.

Vault KV v2 path:

```text
secret/soc-backend
```

Validated secrets include:

```text
SECRET_KEY
SOC_INGESTION_API_KEY
GROQ_API_KEY
ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
OTX_API_KEY
```

Real secret values must never be stored in source control.

The current Vault service runs in development mode and requires production hardening for a real deployment.

---

## 17. Network Security and HTTPS

Traefik v3.6 acts as the reverse proxy.

The main backend entry point is:

```text
https://soc.local
```

The architecture follows:

```text
Client
  |
  | HTTPS
  v
Traefik
  |
  v
FastAPI Backend
```

Plain HTTP requests are redirected to HTTPS.

Local TLS certificates and private keys are excluded from Git.

---

## 18. Monitoring and Observability

Prometheus collects metrics exposed by the FastAPI backend.

Grafana provides visualization dashboards.

The monitoring architecture is:

```text
FastAPI
   |
   v
Prometheus
   |
   v
Grafana
```

SOC-oriented metrics include:

- total incidents
- severity distribution
- MTTD
- MTTR
- workflow-related information

---

## 19. Docker Compose Infrastructure

The prototype uses Docker Compose to orchestrate its main infrastructure.

Core services include:

```text
PostgreSQL
Redis
Qdrant
FastAPI Backend
Prometheus
Grafana
HashiCorp Vault
Keycloak
Traefik
```

The backend Docker image uses:

```text
Python 3.13
```

Docker networking allows services to communicate using internal service names rather than host addresses.

---

## 20. Security Controls

The architecture includes multiple defense mechanisms:

- JWT authentication
- RBAC authorization
- Keycloak OIDC support
- HTTPS/TLS
- Traefik reverse proxy
- HashiCorp Vault
- ingestion API-key authentication
- constant-time ingestion-key comparison
- restricted CORS configuration
- sanitized API errors
- RAG prompt-injection protections
- Human-in-the-Loop
- SOAR approval gates
- SOAR dry-run mode
- audit logging
- secret exclusion from Git

These controls reduce the risk of unauthorized access, credential exposure, and unsafe automated response actions.

---

## 21. Representative End-to-End Flow

The integrated architecture supports the following workflow:

```text
Security Event
     |
     v
Wazuh / Suricata
     |
     v
Authenticated Ingestion
     |
     v
Normalization
     |
     v
Alert / Incident
     |
     v
Correlation
     |
     v
Triage
     |
     v
Hybrid Machine Learning
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
Human Review
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

A representative high-risk workflow has been validated through the full agent pipeline, including a Human-in-the-Loop interruption and authorized resume.

This demonstrates integration of the principal SOC components but does not imply that every possible attack category, security source, or response action has been tested end-to-end.

---

## 22. Prototype Limitations

The current architecture is a functional academic prototype rather than a production SOC deployment.

Current limitations include:

- MISP support is implemented but not connected to a live MISP instance.
- Shuffle is not integrated into the main prototype.
- Vault runs in development mode.
- Keycloak runs in development mode.
- destructive SOAR actions are disabled by default.
- Kubernetes/K3s deployment is future work.
- commercial EDR integration is outside the current scope.
- full cloud-provider integration is outside the current scope.
- large-scale production load testing has not been performed.
- not every attack category has been validated end-to-end.

---

## 23. Future Architecture

The architecture can be extended toward a production-oriented deployment with:

```text
                    Internet / SOC Users
                             |
                             v
                      Secure Ingress
                             |
                             v
                       Traefik / TLS
                             |
                             v
                  +----------+----------+
                  |                     |
                  v                     v
             SOC Frontend          FastAPI API
                                        |
                         +--------------+--------------+
                         |                             |
                         v                             v
                   AI / ML Services              SOC Services
                         |                             |
             +-----------+-----------+                 |
             |                       |                 |
             v                       v                 v
          Qdrant                 LLM Provider      PostgreSQL
                                                       |
                                                       v
                                                  Redis Cache
```

Potential future improvements include:

- K3s/Kubernetes orchestration
- production Vault deployment
- production Keycloak deployment
- scalable worker architecture
- additional SIEM/EDR integrations
- cloud security telemetry
- external SOAR integration
- advanced model monitoring
- large-scale performance testing
- high-availability infrastructure

---

## 24. Architecture Summary

The AI-Powered SOC Analyst combines traditional SOC monitoring with AI-assisted investigation and controlled automation.

Its principal architecture can be summarized as:

```text
Collect
  -> Normalize
  -> Correlate
  -> Detect
  -> Enrich
  -> Retrieve Knowledge
  -> Investigate with AI
  -> Map to MITRE ATT&CK
  -> Human Validation
  -> Respond
  -> Report
  -> Audit
```

The design keeps the human analyst in control of sensitive response decisions while using Machine Learning, Threat Intelligence, RAG, LLM reasoning, and multi-agent orchestration to accelerate SOC investigation and response.