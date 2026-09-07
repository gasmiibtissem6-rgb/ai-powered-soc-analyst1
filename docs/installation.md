# AI-Powered SOC Analyst — Installation Guide

## 1. Overview

This document describes how to install and run the AI-Powered SOC Analyst prototype.

The recommended environment uses Docker Compose and includes the main backend infrastructure:

- FastAPI backend
- Python 3.13
- PostgreSQL
- Redis
- Qdrant
- HashiCorp Vault
- Keycloak
- Traefik
- Prometheus
- Grafana

Wazuh and Suricata can provide external security telemetry to the backend ingestion APIs.

---

## 2. Prerequisites

The recommended development environment is Linux.

Required tools:

- Git
- Docker
- Docker Compose
- Python 3.13 for direct local backend development

Verify the installation:

```bash
git --version
docker --version
docker compose version
```

For local Python development:

```bash
python3.13 --version
```

The authoritative backend Docker image uses:

```text
Python 3.13
```

---

## 3. Clone the Repository

Clone the project:

```bash
git clone <repository-url>
cd ai-powered-soc-analyst
```

The main project structure includes:

```text
ai-powered-soc-analyst/
|
├── backend/
├── data/
├── docs/
├── docker-compose.yml
└── README.md
```

---

## 4. Backend Environment Configuration

Move to the backend directory:

```bash
cd backend
```

Create the local environment file from the provided example:

```bash
cp .env.example .env
```

Do not commit `.env`.

The `.env.example` file contains placeholders only.

---

## 5. Core Environment Variables

The backend configuration includes the following categories.

### Authentication

```env
SECRET_KEY=change_me_with_a_secure_random_secret
SOC_INGESTION_API_KEY=change_me_with_a_secure_ingestion_key
```

`SECRET_KEY` is used by the local authentication mechanism.

`SOC_INGESTION_API_KEY` protects machine-to-machine ingestion endpoints such as Wazuh and Suricata.

Never reuse the example values in a real deployment.

---

## 6. Database, Cache and Vector Store

Example local configuration:

```env
DATABASE_URL=postgresql://soc_admin:your_password@localhost:5432/soc_db
REDIS_URL=redis://localhost:6379/0
QDRANT_URL=http://localhost:6333
```

When the backend runs through Docker Compose, internal service addresses are provided through the Docker network.

The main storage components are:

```text
PostgreSQL -> relational SOC data
Redis      -> Threat Intelligence cache
Qdrant     -> RAG vector storage
```

---

## 7. LLM Configuration

The current prototype uses the Groq OpenAI-compatible API.

Example:

```env
GROQ_API_KEY=your_groq_api_key_here
LLM_MODEL=openai/gpt-oss-120b
LLM_BASE_URL=https://api.groq.com/openai/v1
```

The real API key must never be committed to Git.

The original project specification considered Kimi K3. The current prototype uses Groq because the configured Moonshot/Kimi service was not available within the prototype API quota.

---

## 8. Threat Intelligence Configuration

The prototype supports several Threat Intelligence providers.

### AbuseIPDB

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

### VirusTotal

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

### AlienVault OTX

```env
OTX_API_KEY=your_otx_api_key_here
```

These three providers have been validated in the prototype.

### MISP

MISP support is optional.

```env
MISP_URL=
MISP_API_KEY=
MISP_VERIFY_SSL=true
```

If MISP is not configured, the provider returns a controlled `not_configured` status.

A live MISP instance is not required to run the current prototype.

---

## 9. SOAR Configuration

The prototype uses safe defaults.

```env
SOAR_EXECUTION_MODE=dry_run
SOAR_ENABLE_BLOCK_IP=false
SOAR_ENABLE_ISOLATE_ENDPOINT=false
SOAR_ENABLE_DISABLE_USER=false
SOAR_ENABLE_SEND_NOTIFICATION=false
```

These values prevent disruptive response actions from being executed against real infrastructure.

For the academic prototype, keeping:

```text
SOAR_EXECUTION_MODE=dry_run
```

is recommended.

---

## 10. Vault Configuration

HashiCorp Vault is used for centralized secret management.

Example backend configuration:

```env
VAULT_ADDR=
VAULT_TOKEN=
VAULT_MOUNT_POINT=secret
VAULT_SECRET_PATH=soc-backend
```

The Docker Compose environment provides the internal Vault address to the backend.

The configured KV v2 path is:

```text
secret/soc-backend
```

The prototype has been validated with secrets including:

```text
SECRET_KEY
SOC_INGESTION_API_KEY
GROQ_API_KEY
ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
OTX_API_KEY
```

The application Secret Manager attempts to resolve secrets from Vault and can fall back to application configuration when appropriate.

### Important Security Note

The current Docker Compose configuration uses Vault in development mode.

This is acceptable for the academic prototype but is not appropriate for a production SOC deployment.

Production deployment requires:

- persistent Vault storage
- secure initialization
- unseal management
- restricted policies
- non-root application tokens
- TLS
- token rotation

---

## 11. Local Python Environment

Docker Compose is the recommended prototype execution environment.

For direct backend development, create a Python 3.13 virtual environment:

```bash
cd backend

python3.13 -m venv venv
source venv/bin/activate
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

The Docker build installs CPU-only PyTorch separately before the remaining requirements.

For a local environment, install the CPU build when appropriate:

```bash
python -m pip install \
  --index-url https://download.pytorch.org/whl/cpu \
  torch
```

Then install the backend requirements:

```bash
python -m pip install -r requirements.txt
```

---

## 12. Database Migrations

The backend uses Alembic.

Apply migrations with:

```bash
cd backend
alembic upgrade head
```

This prepares the PostgreSQL schema required by the application.

---

## 13. Docker Compose Deployment

From the project root:

```bash
cd ai-powered-soc-analyst
```

Build and start the services:

```bash
docker compose up -d --build
```

Check the running containers:

```bash
docker compose ps
```

The prototype stack includes services for:

```text
PostgreSQL
Redis
Qdrant
FastAPI Backend
Prometheus
Grafana
Vault
Keycloak
Traefik
```

---

## 14. Backend Docker Image

The backend Dockerfile uses:

```dockerfile
FROM python:3.13-slim
```

The image installs required system packages and CPU-only PyTorch before installing the remaining Python dependencies.

The FastAPI server starts with:

```text
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 15. Verify Python Runtime

Verify the Python version inside the actual backend container:

```bash
docker exec soc-backend python --version
```

Expected major/minor version:

```text
Python 3.13
```

The container runtime should be treated as authoritative for the Docker prototype.

---

## 16. Verify Container Status

Run:

```bash
docker compose ps
```

Check that the required services are running.

If a service is not healthy, inspect its logs without exposing secrets:

```bash
docker compose logs --tail=100 <service-name>
```

Avoid copying logs containing credentials, access tokens, API keys, or other sensitive values into public issues or documentation.

---

## 17. HTTPS Configuration

Traefik provides the HTTPS entry point.

The validated backend hostname is:

```text
soc.local
```

For a local prototype, ensure that `soc.local` resolves to the machine hosting Traefik.

A typical local hosts entry is:

```text
127.0.0.1 soc.local
```

The exact address may differ if the Docker environment is hosted on another machine or virtual machine.

Do not commit local TLS private keys to Git.

---

## 18. Verify HTTPS

Once the stack is running, verify the backend health endpoint:

```bash
curl -k -I https://soc.local/health
```

Expected result:

```text
HTTP/2 200
```

The `-k` option is appropriate only for a local prototype using a locally generated or otherwise untrusted development certificate.

Production environments should use a trusted certificate and normal TLS verification.

---

## 19. HTTP to HTTPS Redirect

The prototype redirects HTTP traffic to HTTPS.

Test:

```bash
curl -I http://soc.local/health
```

The expected behavior is an HTTP redirect toward the HTTPS endpoint.

---

## 20. Swagger and OpenAPI

FastAPI exposes interactive API documentation.

Swagger UI:

```text
https://soc.local/docs
```

OpenAPI schema:

```text
https://soc.local/openapi.json
```

Verify from the terminal:

```bash
curl -k -I https://soc.local/docs
curl -k -I https://soc.local/openapi.json
```

The current validated prototype exposes 45 OpenAPI paths.

---

## 21. PostgreSQL

PostgreSQL is the primary persistent database.

It stores information such as:

- users
- alerts
- incidents
- AI analyses
- reports
- SOAR actions
- audit information

The Docker Compose service uses persistent storage.

Database credentials must not be committed to Git.

---

## 22. Redis

Redis provides Threat Intelligence caching.

Check that Redis is running:

```bash
docker compose ps
```

The backend Docker environment uses the Redis service through the Docker network.

A typical internal address is:

```text
redis://redis:6379/0
```

The Threat Intelligence enrichment cache uses keys such as:

```text
soc:ti:ip:{ip_address}
```

---

## 23. Qdrant

Qdrant provides vector storage for the RAG subsystem.

The backend Docker environment communicates with Qdrant through:

```text
http://qdrant:6333
```

The current RAG collection is:

```text
soc_knowledge
```

The knowledge base is indexed using LlamaIndex and Hugging Face embeddings.

---

## 24. Keycloak

Keycloak provides OpenID Connect authentication.

Prototype configuration includes:

```text
Realm: soc
Client: soc-backend
```

The backend validates Keycloak tokens using the provider's JWKS keys.

Keycloak runs in development mode in the current Docker Compose prototype.

For a production deployment, Keycloak must be configured with production security settings and persistent operational configuration.

---

## 25. Prometheus

Prometheus collects backend metrics.

The backend exposes monitoring endpoints including:

```text
GET /metrics
GET /metrics/dashboard
GET /metrics/severity
```

Prometheus periodically collects relevant application metrics.

---

## 26. Grafana

Grafana provides visualization for SOC metrics collected through Prometheus.

The prototype dashboard can display information such as:

- total incidents
- critical incidents
- high-severity incidents
- medium-severity incidents
- MTTD
- MTTR

Development credentials or default prototype credentials must be changed before any production deployment.

---

## 27. Wazuh Integration

Wazuh is an external security-monitoring source.

The backend ingestion endpoint is:

```text
POST /wazuh/alerts
```

Requests must provide the configured ingestion API key.

The prototype has been validated with real Wazuh alerts from a monitored Linux endpoint.

The Wazuh environment can use Filebeat and Wazuh Indexer/OpenSearch-compatible storage independently of the main Docker Compose application stack.

---

## 28. Suricata Integration

Suricata provides network IDS/IPS telemetry.

The backend ingestion endpoint is:

```text
POST /suricata/alerts
```

The endpoint is protected by the ingestion API key.

Suricata network information can also be used by the Machine Learning pipeline when the required features are available.

---

## 29. Run the Backend Without Docker

For development purposes, FastAPI can be started directly.

From `backend/`:

```bash
source venv/bin/activate

uvicorn app.main:app \
  --reload \
  --host 0.0.0.0 \
  --port 8000
```

When running outside Docker, local dependency addresses such as PostgreSQL, Redis, and Qdrant must be reachable according to the values configured in `.env`.

---

## 30. Run Automated Tests

The recommended test command uses the authoritative Python 3.13 backend container:

```bash
docker exec -w /app soc-backend python -m pytest -q
```

Current validated backend result:

```text
69 passed
```

SOAR-specific tests:

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

Warnings may still be produced by third-party libraries or deprecated APIs; they do not necessarily indicate test failures.

---

## 31. GitHub Actions

The repository includes a backend GitHub Actions workflow.

The CI pipeline uses Python 3.13 and runs automated backend tests.

A successful local change should normally be checked with:

```bash
git diff --check
git status --short
```

before commit.

After pushing a commit, the GitHub Actions result should be verified.

---

## 32. Security Verification

Basic security checks include verifying that unauthenticated requests cannot access protected resources.

The prototype includes:

- JWT authentication
- RBAC
- Keycloak OIDC
- ingestion API-key authentication
- HTTPS
- Vault secret management
- restricted CORS
- sanitized errors
- Human-in-the-Loop
- SOAR approval gates
- dry-run execution

Never test authentication by printing real tokens or secrets into terminal history or documentation.

---

## 33. Secret Handling Rules

Never commit:

```text
.env
API keys
passwords
JWT access tokens
Vault tokens
private keys
TLS private keys
provider credentials
```

The repository should contain only placeholders in:

```text
backend/.env.example
```

Sensitive application secrets should preferably be retrieved from Vault.

---

## 34. Useful Verification Commands

Check containers:

```bash
docker compose ps
```

Check backend Python:

```bash
docker exec soc-backend python --version
```

Check health:

```bash
curl -k -I https://soc.local/health
```

Check Swagger:

```bash
curl -k -I https://soc.local/docs
```

Check OpenAPI:

```bash
curl -k -I https://soc.local/openapi.json
```

Run tests:

```bash
docker exec -w /app soc-backend python -m pytest -q
```

Check Git changes:

```bash
git diff --check
git status --short
```

---

## 35. Troubleshooting

### Backend container does not start

Check:

```bash
docker compose ps
```

Then inspect the backend logs:

```bash
docker compose logs --tail=100 backend
```

Do not publish logs containing sensitive information.

### PostgreSQL connection failure

Verify:

- PostgreSQL container status
- `DATABASE_URL`
- Docker network connectivity
- database credentials

### Redis connection failure

Verify:

- Redis container status
- `REDIS_URL`
- Docker network connectivity

### Qdrant connection failure

Verify:

- Qdrant container status
- `QDRANT_URL`
- port `6333`
- Docker network connectivity

### Groq authentication failure

Verify that `GROQ_API_KEY` is configured through the approved secret-management path.

Do not print the key.

### Threat Intelligence provider failure

Verify that the relevant provider API key is configured.

The system is designed to handle unavailable providers without exposing internal credentials.

### MISP returns `not_configured`

This is expected when no MISP server and API key have been configured.

MISP is optional in the current prototype.

### HTTPS certificate warning

A local development certificate may not be trusted by the operating system.

For local testing only:

```bash
curl -k https://soc.local/health
```

Do not disable TLS verification in a production environment.

---

## 36. Prototype vs Production

The current installation is intended for development, demonstration, and academic validation.

Before production deployment, additional work is required, including:

- production Vault deployment
- production Keycloak deployment
- trusted TLS certificates
- credential rotation
- secure network segmentation
- least-privilege service accounts
- production database hardening
- backup and recovery
- high availability
- centralized production logging
- infrastructure monitoring
- large-scale performance testing
- Kubernetes/K3s deployment if required

---

## 37. Installation Summary

The recommended prototype startup process is:

```text
Clone Repository
      |
      v
Create backend/.env
      |
      v
Configure Required Secrets
      |
      v
Start Docker Compose
      |
      v
Verify Containers
      |
      v
Apply / Verify Database State
      |
      v
Verify HTTPS
      |
      v
Verify Swagger / OpenAPI
      |
      v
Run Automated Tests
      |
      v
Use SOC APIs
```

The Docker Compose environment provides a reproducible platform for demonstrating the backend, AI/ML pipeline, RAG, Threat Intelligence, security controls, monitoring, and Human-in-the-Loop SOAR workflow.