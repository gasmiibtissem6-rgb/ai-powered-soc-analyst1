# AI-Powered SOC Analyst — Security Architecture

## 1. Overview

Security is a core requirement of the AI-Powered SOC Analyst platform.

The prototype implements multiple security layers to protect:

- analyst access
- administrative operations
- security-event ingestion
- application secrets
- API communications
- AI-assisted workflows
- automated response actions
- internal error information

The main implemented security controls include:

- JWT authentication
- Role-Based Access Control (RBAC)
- Keycloak / OpenID Connect
- HTTPS through Traefik
- HashiCorp Vault secret management
- machine-to-machine ingestion authentication
- restricted CORS
- sanitized error handling
- RAG prompt-injection protections
- Human-in-the-Loop approval
- SOAR approval gates
- SOAR dry-run mode
- audit logging

---

## 2. Defense-in-Depth Model

The platform follows a defense-in-depth approach.

```text
                    SOC User
                       |
                       v
                 HTTPS / TLS
                       |
                       v
                    Traefik
                       |
                       v
              Authentication Layer
             JWT / Keycloak OIDC
                       |
                       v
                     RBAC
                       |
                       v
                FastAPI Backend
                       |
          +------------+-------------+
          |                          |
          v                          v
   Application Logic          Secret Manager
          |                          |
          |                          v
          |                         Vault
          |
          v
     SOC Workflow
          |
    +-----+------+
    |            |
    v            v
   HITL        SOAR
                 |
                 v
          Approval / Dry Run
                 |
                 v
             Audit Trail
```

No single control is considered sufficient on its own.

---

## 3. Local Authentication

The backend supports local user authentication.

Authentication endpoints include:

```http
POST /auth/register
POST /auth/login
GET  /auth/me
```

After successful authentication, the backend issues a JWT access token.

Protected API requests use:

```text
Authorization: Bearer <access_token>
```

Real access tokens must never be included in documentation, screenshots, logs intended for publication, or Git commits.

---

## 4. JWT Security

JWT is used for local authenticated sessions.

The backend validates tokens before granting access to protected resources.

Invalid or expired authentication credentials are rejected.

A typical unauthorized response is:

```text
401 Unauthorized
```

The prototype has been validated to reject expired or invalid authentication rather than exposing protected resources.

JWT signing secrets are treated as sensitive configuration.

The signing secret must never be committed to Git.

---

## 5. Role-Based Access Control

Authentication determines who the user is.

RBAC determines what the authenticated user is allowed to do.

The prototype uses roles including:

```text
analyst
admin
```

Sensitive operations require appropriate authorization.

Examples include:

- SOC investigation operations
- SOAR administration
- Human-in-the-Loop workflow resume
- administrative actions

An authenticated user without the required role receives an authorization failure such as:

```text
403 Forbidden
```

This separates authentication from authorization.

---

## 6. Keycloak and OpenID Connect

The platform also supports Keycloak-based authentication.

Prototype configuration includes:

```text
Realm: soc
Client: soc-backend
```

The backend validates Keycloak access tokens using the provider's JWKS public keys.

The general authentication flow is:

```text
User
 |
 v
Keycloak
 |
 v
Authentication
 |
 v
Access Token
 |
 v
FastAPI
 |
 v
JWKS Validation
 |
 v
RBAC
 |
 v
Protected SOC Resource
```

Keycloak token validation has been verified against protected backend resources.

---

## 7. Frontend Authentication Model

For a future or separate frontend application, the intended authentication mechanism is:

```text
Authorization Code Flow + PKCE
```

This approach avoids embedding privileged client secrets in browser applications.

The frontend should not store backend secrets or provider API keys.

---

## 8. Keycloak Prototype Limitation

The current Keycloak container runs in development mode.

This configuration is appropriate for prototype and academic validation only.

A production deployment should use:

- production Keycloak mode
- persistent database storage
- secure administrator credentials
- trusted HTTPS
- restricted management access
- appropriate token lifetimes
- secure client configuration
- credential rotation

---

## 9. Machine-to-Machine Ingestion Security

Wazuh and Suricata do not authenticate as interactive analysts.

They use a dedicated ingestion authentication mechanism.

Protected ingestion endpoints:

```http
POST /wazuh/alerts
POST /suricata/alerts
```

The expected header is:

```text
X-SOC-Ingestion-Key
```

The value is compared against the configured:

```text
SOC_INGESTION_API_KEY
```

This separates machine ingestion authentication from analyst authentication.

---

## 10. Constant-Time API Key Comparison

The ingestion key validation uses a constant-time comparison mechanism.

This reduces information leakage through timing differences when comparing secret values.

Conceptually:

```text
Received Key
     |
     v
Constant-Time Comparison
     |
 +---+---+
 |       |
 v       v
Valid  Invalid
 |       |
 v       v
Allow   401
```

The real ingestion key must never be printed or committed.

---

## 11. Missing Ingestion Configuration

The backend distinguishes between:

- invalid credentials
- missing server-side security configuration

A request with an invalid ingestion key is rejected.

If the required ingestion secret is unavailable from backend configuration, the service can return a controlled service error rather than silently accepting ingestion.

This follows a fail-closed approach.

---

## 12. Secret Management

HashiCorp Vault is used as the primary centralized secret-management mechanism in the prototype.

The backend includes a Secret Manager abstraction.

The resolution strategy is conceptually:

```text
Application requests secret
          |
          v
       Vault
          |
     +----+----+
     |         |
 Available   Unavailable
     |         |
     v         v
Use Vault   Controlled
  Value     Configuration
              Fallback
```

This avoids hard-coding secrets directly in application source code.

---

## 13. Vault Configuration

The prototype uses the Vault KV v2 engine.

Configured path:

```text
secret/soc-backend
```

The validated prototype secret set includes:

```text
SECRET_KEY
SOC_INGESTION_API_KEY
GROQ_API_KEY
ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
OTX_API_KEY
```

Only secret names are documented.

Real values must never appear in the repository.

---

## 14. Vault Fallback Strategy

The backend Secret Manager uses Vault first.

Application configuration can be used as a fallback where appropriate.

This supports local development while allowing centralized secret management in the Docker prototype.

The fallback mechanism must not be interpreted as permission to commit credentials.

Files such as:

```text
.env
```

must remain excluded from Git.

---

## 15. Vault Prototype Limitation

The current Docker Compose deployment runs Vault in development mode.

Development mode is not appropriate for a real SOC production deployment.

Production Vault deployment requires controls such as:

- persistent encrypted storage
- secure initialization
- unseal management
- restricted policies
- least-privilege application tokens
- token rotation
- audit devices
- TLS
- secure backup and recovery

The prototype validates application integration, not production Vault operations.

---

## 16. HTTPS

The backend is exposed through Traefik using HTTPS.

Validated entry point:

```text
https://soc.local
```

The network flow is:

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

HTTPS protects API traffic against passive network interception.

---

## 17. HTTP Redirection

Plain HTTP traffic is redirected to HTTPS.

Conceptually:

```text
http://soc.local
       |
       v
   HTTP Redirect
       |
       v
https://soc.local
```

The redirect behavior has been validated in the prototype.

---

## 18. Development TLS Certificates

The local prototype may use a locally generated or untrusted certificate.

For local testing only, commands may use:

```bash
curl -k https://soc.local/health
```

The `-k` option disables certificate verification and must not be used as a production security practice.

Production environments should use trusted certificates and normal TLS validation.

TLS private keys must never be committed to Git.

---

## 19. CORS

The FastAPI backend uses restricted Cross-Origin Resource Sharing configuration.

The validated frontend origin is restricted rather than allowing unrestricted browser origins.

Prototype allowed origin:

```text
https://soc.local
```

Restricting CORS reduces exposure to unauthorized browser-based cross-origin requests.

CORS is not an authentication mechanism and must be used together with authentication and authorization.

---

## 20. Error Sanitization

API errors are sanitized to reduce exposure of internal implementation details.

The backend avoids returning raw exception information where this could reveal:

- credentials
- provider details
- internal URLs
- stack information
- implementation internals
- sensitive configuration

The general pattern is:

```text
Internal Exception
       |
       v
Server-Side Handling
       |
       v
Sanitized API Error
       |
       v
Client
```

Detailed sensitive exceptions should not be returned directly to API consumers.

---

## 21. Threat Intelligence Security

Threat Intelligence providers require API credentials.

The prototype integrates:

- AbuseIPDB
- VirusTotal
- AlienVault OTX

Provider API keys are treated as secrets.

They can be resolved through the backend Secret Manager.

They must never be:

- committed to Git
- returned through API responses
- included in documentation
- printed in shared terminal output

---

## 22. Optional MISP Security

MISP support is implemented but no live MISP instance is configured in the prototype.

Configuration fields include:

```text
MISP_URL
MISP_API_KEY
MISP_VERIFY_SSL
```

When no provider is configured, the integration returns a controlled:

```text
not_configured
```

status.

The absence of MISP does not disable the other Threat Intelligence providers.

---

## 23. LLM Credential Security

The current prototype uses the Groq API.

Sensitive configuration includes:

```text
GROQ_API_KEY
```

The key must never be sent to frontend clients.

Only the backend should communicate directly with the provider using the configured secret.

The current model is:

```text
openai/gpt-oss-120b
```

The model identifier is not secret.

The API credential is secret.

---

## 24. RAG Security

Retrieval-Augmented Generation introduces additional security considerations because retrieved documents influence LLM context.

The prototype includes prompt-injection protections for retrieved content.

The design principle is:

```text
Retrieved Knowledge
       |
       v
Treat as Untrusted Context
       |
       v
Security Instructions
       |
       v
LLM Investigation
```

Retrieved documents should provide evidence and context but must not override trusted system-level security instructions.

---

## 25. Prompt Injection

A malicious or compromised knowledge-base document could attempt to include instructions such as:

```text
Ignore previous instructions...
Reveal credentials...
Execute an action...
```

The RAG layer is designed to treat retrieved material as untrusted data rather than trusted system instructions.

Sensitive operations remain protected independently through:

- backend authorization
- HITL
- SOAR approval gates
- server-side execution controls

Therefore an LLM response alone cannot bypass backend authorization.

---

## 26. AI Output Trust Model

LLM output is treated as analytical assistance, not as an unquestionable security decision.

The AI may propose:

- risk level
- explanation
- recommendation
- MITRE ATT&CK mapping
- response recommendations

These outputs are combined with evidence from:

- security events
- Machine Learning
- Threat Intelligence
- RAG
- correlation
- analyst review

For high-risk actions, additional human approval is required.

---

## 27. Machine Learning Trust Model

Machine Learning predictions are also treated as evidence rather than absolute truth.

The hybrid pipeline can produce conflicting results.

Example:

```text
Random Forest    -> BENIGN
XGBoost          -> BENIGN
Isolation Forest -> ANOMALY
```

The platform preserves this disagreement.

An anomaly does not automatically prove malicious activity.

The Investigation Agent receives the individual model evidence and reasons about it together with other SOC information.

---

## 28. Human-in-the-Loop

Human-in-the-Loop is a central safety mechanism.

High or critical incidents can interrupt the LangGraph workflow before response processing.

```text
Investigation
      |
      v
Risk Evaluation
      |
 +----+-------------+
 |                  |
 v                  v
Low / Medium    High / Critical
 |                  |
 v                  v
Continue          Interrupt
                     |
                     v
                Human Review
                  /       \
                 /         \
            Approve       Reject
               |             |
               v             v
           Continue      Controlled Stop
```

This keeps an authorized human in control of sensitive response decisions.

---

## 29. HITL Authorization

Workflow resume is exposed through:

```http
POST /agents/resume/{thread_id}
```

The resume operation is restricted to authorized administrative users.

This prevents an ordinary unauthenticated client from approving its own high-risk workflow.

---

## 30. SOAR Security

The internal SOAR implementation supports response actions such as:

- create ticket
- block IP
- isolate endpoint
- disable user
- send notification

Potentially disruptive actions are protected through:

- authentication
- RBAC
- approval state
- execution-mode controls
- action-specific safety flags
- audit logging

---

## 31. SOAR Approval Gate

The response lifecycle follows a controlled state transition.

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
       Execution
           |
           v
       Audit Log
```

Approval and execution are separate operations.

This prevents a proposed response from automatically becoming an executed response.

---

## 32. SOAR Dry-Run Mode

The prototype defaults to:

```env
SOAR_EXECUTION_MODE=dry_run
```

Destructive action flags are disabled by default:

```env
SOAR_ENABLE_BLOCK_IP=false
SOAR_ENABLE_ISOLATE_ENDPOINT=false
SOAR_ENABLE_DISABLE_USER=false
SOAR_ENABLE_SEND_NOTIFICATION=false
```

This allows response workflows to be demonstrated safely.

A successful dry-run means that the workflow was simulated; it does not mean that a real host, IP, or user account was modified.

---

## 33. SOAR Audit Logging

SOAR actions generate audit information.

The audit trail can record lifecycle information such as:

- action creation
- approval
- rejection
- execution request
- simulation result
- execution status

Logs can be retrieved through:

```http
GET /soar/{action_id}/logs
```

Auditability is important because response actions may affect protected infrastructure.

---

## 34. Shuffle Status

Shuffle was considered and partially evaluated as an external SOAR option.

However:

```text
Shuffle is not integrated into the main prototype stack.
```

The current validated SOAR implementation is the internal backend module.

Documentation must not claim that Shuffle currently executes production response workflows.

---

## 35. Input Validation

FastAPI and Pydantic provide structured request validation.

Malformed or invalid request bodies can be rejected before reaching application logic.

A common validation response is:

```text
422 Unprocessable Entity
```

Validation helps reduce unexpected data reaching security-sensitive services.

---

## 36. SQL Data Access

The backend uses SQLAlchemy for relational database operations.

Application data access should use ORM/query abstractions rather than manually concatenating untrusted input into raw SQL strings.

This reduces SQL-injection exposure when the ORM is used correctly.

Database credentials remain server-side secrets.

---

## 37. Security Headers and Reverse Proxy Boundary

Traefik forms the external reverse-proxy boundary of the Docker prototype.

External clients should access the backend through:

```text
https://soc.local
```

rather than treating internal Docker service addresses as public endpoints.

Internal addresses such as:

```text
http://backend:8000
http://redis:6379
http://qdrant:6333
```

belong to the service network and should not be treated as public application interfaces.

---

## 38. Secret Repository Hygiene

The repository must never contain real:

```text
API keys
JWT signing secrets
access tokens
refresh tokens
passwords
Vault tokens
private keys
TLS private keys
provider credentials
```

`backend/.env.example` must contain placeholders only.

The real:

```text
backend/.env
```

must remain excluded from Git.

---

## 39. Safe Diagnostic Practices

Security diagnostics should avoid commands that expose secrets.

Avoid commands such as:

```text
cat .env
printenv
vault kv get ... with raw values in shared output
echo $API_KEY
```

Prefer validation that reports only whether a secret is configured.

Example concept:

```text
GROQ_API_KEY: AVAILABLE
```

rather than printing its value.

---

## 40. Logging Security

Application logs should avoid exposing:

- API keys
- passwords
- authorization headers
- JWTs
- Vault tokens
- private keys

When troubleshooting, logs should be reviewed before they are shared externally.

Error sanitization should be preserved even when detailed internal logging is available.

---

## 41. Security Monitoring

The platform itself exposes SOC metrics through:

```http
GET /metrics
GET /metrics/severity
GET /metrics/dashboard
GET /prometheus
```

Prometheus collects operational metrics.

Grafana provides dashboard visualization.

Monitoring can help identify unusual system behavior, but production monitoring should also cover infrastructure-level security events.

---

## 42. CI Security

GitHub Actions runs automated backend tests.

The CI environment uses placeholder configuration values rather than real production credentials.

Automated testing helps detect regressions affecting:

- authentication
- RBAC
- ingestion security
- SOAR
- Vault behavior
- API behavior

CI success does not replace a dedicated security audit, but it provides continuous regression protection.

---

## 43. Validated Security Controls

The prototype has validated behavior for major security mechanisms, including:

```text
JWT authentication
RBAC restrictions
Keycloak token validation
JWKS retrieval
HTTPS access
HTTP -> HTTPS redirect
restricted CORS
Wazuh ingestion authentication
Suricata ingestion authentication
Vault secret resolution
SOAR approval workflow
SOAR dry-run execution
Human-in-the-Loop resume authorization
sanitized API errors
RAG prompt-injection protections
```

These validations apply to the prototype environment.

They should not be interpreted as a formal penetration-test certification.

---

## 44. Security Boundaries

The platform separates several trust boundaries.

```text
                 External User
                      |
                      v
               HTTPS Boundary
                      |
                      v
              Authentication
                      |
                      v
                   RBAC
                      |
                      v
               Backend Logic
                 /       \
                /         \
               v           v
       External APIs    Internal Data
       TI / LLM         PostgreSQL
                         Redis
                         Qdrant
                           |
                           v
                         Vault
```

External provider responses are treated as external data.

Retrieved RAG documents are treated as contextual data.

LLM output is treated as advisory analysis.

Sensitive execution remains controlled by backend authorization and human approval.

---

## 45. Production Hardening Requirements

The current system is an academic prototype.

Before production deployment, additional hardening is required.

### Vault

Replace development mode with:

- persistent storage
- proper initialization
- least-privilege policies
- non-root application authentication
- TLS
- audit logging
- rotation procedures

### Keycloak

Replace development mode with:

- production deployment
- persistent database
- secure administrator access
- hardened client configuration
- trusted TLS
- appropriate session/token policies

### TLS

Use trusted certificates.

Do not use:

```text
curl -k
```

as an operational production practice.

### SOAR

Before enabling destructive actions:

- validate each integration
- implement rollback where possible
- enforce least privilege
- maintain HITL for high-impact operations
- audit all actions
- test in an isolated environment

### Infrastructure

Production infrastructure should also include:

- network segmentation
- firewall policies
- backup and recovery
- service-account isolation
- secure container configuration
- vulnerability management
- dependency monitoring
- centralized security logging
- availability monitoring

---

## 46. Security Limitations

The current prototype has known limitations:

- Vault runs in development mode.
- Keycloak runs in development mode.
- local development certificates may not be publicly trusted.
- destructive SOAR operations are disabled.
- MISP is not connected to a live instance.
- Shuffle is not integrated into the main stack.
- the system has not undergone a formal external penetration test.
- large-scale production security testing is outside the current project scope.

These limitations should be clearly distinguished from implemented security controls.

---

## 47. Security Summary

The security model follows the principle:

```text
Authenticate
    |
    v
Authorize
    |
    v
Protect Secrets
    |
    v
Encrypt Transport
    |
    v
Validate Inputs
    |
    v
Treat AI Evidence Carefully
    |
    v
Require Human Approval
    |
    v
Execute Safely
    |
    v
Audit Actions
```

The architecture does not rely on AI as a security boundary.

Authentication, RBAC, Vault, HTTPS, ingestion authentication, Human-in-the-Loop, SOAR approval gates, and server-side execution controls remain responsible for enforcing sensitive operations.

AI, Machine Learning, Threat Intelligence, and RAG provide analytical assistance while the backend and human analyst retain control of security-sensitive actions.