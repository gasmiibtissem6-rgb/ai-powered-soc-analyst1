# AI-Powered SOC Analyst — Threat Intelligence and SOAR

## 1. Overview

The AI-Powered SOC Analyst integrates Threat Intelligence and Security Orchestration, Automation and Response (SOAR) capabilities into the incident investigation workflow.

Threat Intelligence enriches security indicators with external reputation and contextual information.

SOAR manages proposed response actions while preserving analyst control through authorization, approval gates, Human-in-the-Loop validation, execution safety controls, and audit logging.

The current prototype includes:

- AbuseIPDB integration
- VirusTotal integration
- AlienVault OTX integration
- optional MISP integration
- Redis-based Threat Intelligence caching
- incident-level Threat Intelligence enrichment
- internal SOAR workflow
- Human-in-the-Loop approval
- dry-run execution
- response action audit logging

---

## 2. Threat Intelligence Architecture

The Threat Intelligence flow can be represented as:

```text
Security Incident
       |
       v
Extract Indicator
       |
       v
Threat Intelligence Service
       |
       +-------------------+
       |                   |
       v                   v
 Redis Cache         External Providers
       |                   |
       |          +--------+--------+
       |          |        |        |
       |          v        v        v
       |       AbuseIPDB   VT      OTX
       |                            |
       |                     MISP (optional)
       |                            |
       +-------------+--------------+
                     |
                     v
             Normalized Results
                     |
                     v
            Investigation Agent
                     |
                     v
                SOC Report
```

---

## 3. Threat Intelligence Purpose

Threat Intelligence helps the platform answer questions such as:

```text
Has this IP address been reported as malicious?
Is this domain associated with suspicious activity?
Is this URL known by security providers?
Is this file hash associated with malware?
How much external reputation evidence exists?
```

Threat Intelligence is used as investigation evidence.

It does not independently authorize response actions.

---

## 4. Supported Providers

The backend contains integrations for:

```text
AbuseIPDB
VirusTotal
AlienVault OTX
MISP
```

The validated prototype status is:

| Provider | Implementation | Live Prototype Validation |
|---|---|---|
| AbuseIPDB | Implemented | Yes |
| VirusTotal | Implemented | Yes |
| AlienVault OTX | Implemented | Yes |
| MISP | Implemented as optional provider | No — not configured |

MISP must therefore not be described as an active live provider in the current prototype.

---

## 5. AbuseIPDB

AbuseIPDB provides reputation information for IP addresses.

The integration can return information such as:

```text
IP address
abuse confidence score
risk classification
country
usage type
ISP
domain
hostnames
total reports
last reported date
```

The backend converts provider information into a normalized security result.

---

## 6. AbuseIPDB Risk Classification

The AbuseIPDB integration uses the abuse confidence score to derive a simplified risk classification.

Conceptually:

```text
Abuse Score
     |
     +---- Low score ------> SAFE
     |
     +---- Medium score ---> SUSPICIOUS
     |
     +---- High score -----> MALICIOUS
```

This classification is used as supporting investigation evidence.

---

## 7. AbuseIPDB API

IP reputation is available through:

```http
GET /threat-intelligence/ip/{ip_address}
```

Threat Intelligence analysis is also exposed through:

```http
POST /threat-intelligence/analyze
```

Incident-level enrichment is available through:

```http
GET /threat-intelligence/incident/{incident_id}
```

---

## 8. AbuseIPDB Validation

The AbuseIPDB integration has been validated using live provider communication.

A representative lookup used:

```text
8.8.8.8
```

The provider returned a successful response and the backend normalized the result as:

```text
SAFE
```

This confirms that the integration was tested against the external service rather than only mocked locally.

---

## 9. VirusTotal

VirusTotal provides Threat Intelligence for several indicator types.

The implemented integration supports:

```text
IP addresses
domains
URLs
file hashes
```

This provides broader indicator coverage than an IP-only reputation service.

---

## 10. VirusTotal API

The backend exposes:

```http
GET  /threat-intelligence/virustotal/ip/{ip_address}
GET  /threat-intelligence/virustotal/domain/{domain}
POST /threat-intelligence/virustotal/url
GET  /threat-intelligence/virustotal/hash/{file_hash}
```

The URL lookup uses a POST request because the indicator is supplied through request data rather than directly as a path parameter.

---

## 11. VirusTotal Validation

Live VirusTotal communication has been validated.

A representative IP lookup used:

```text
8.8.8.8
```

The API returned successfully and the normalized result was:

```text
SAFE
```

The result confirms working provider authentication and backend communication.

---

## 12. AlienVault OTX

AlienVault Open Threat Exchange (OTX) is integrated as another Threat Intelligence provider.

The backend supports:

```text
IP addresses
domains
URLs
file hashes
```

OTX provides an additional external evidence source that can complement VirusTotal and AbuseIPDB.

---

## 13. OTX API

The implemented endpoints are:

```http
GET  /threat-intelligence/otx/ip/{ip_address}
GET  /threat-intelligence/otx/domain/{domain}
POST /threat-intelligence/otx/url
GET  /threat-intelligence/otx/hash/{file_hash}
```

---

## 14. OTX Validation

Live OTX communication has been validated.

A representative IP lookup used:

```text
8.8.8.8
```

The provider returned successfully and the normalized result was:

```text
SAFE
```

Therefore OTX is an active validated provider in the prototype.

---

## 15. MISP

The backend includes support for MISP as an optional Threat Intelligence provider.

The implementation supports searches for indicators such as:

```text
IP
domain
URL
hash
```

The service communicates conceptually with:

```text
/attributes/restSearch
```

and normalizes returned attributes for the SOC investigation pipeline.

---

## 16. MISP Configuration

MISP configuration uses variables such as:

```env
MISP_URL=
MISP_API_KEY=
MISP_VERIFY_SSL=true
```

The provider is optional.

If the required configuration is absent, the service must not attempt to behave as if MISP were active.

---

## 17. Current MISP Status

The current prototype does not have an active MISP instance configured.

The validated behavior for the unconfigured provider is equivalent to:

```text
Provider: MISP
Status: not_configured
Risk: UNKNOWN
Match count: 0
```

Therefore the correct project description is:

> MISP support is implemented as an optional Threat Intelligence provider but is not activated in the current prototype environment.

---

## 18. Multi-Provider Enrichment

Threat Intelligence evidence can be combined from several providers.

Conceptually:

```text
Suspicious IP
     |
     +----> AbuseIPDB
     |
     +----> VirusTotal
     |
     +----> OTX
     |
     +----> MISP (when configured)
     |
     v
Normalized Enrichment
```

Using multiple sources reduces dependence on one provider.

A provider result remains evidence rather than an absolute security decision.

---

## 19. Incident-Level Enrichment

Threat Intelligence can be requested for an incident through:

```http
GET /threat-intelligence/incident/{incident_id}
```

The service extracts relevant information from the incident and enriches supported indicators.

The resulting context can then be consumed by the SOC investigation workflow.

---

## 20. Threat Intelligence in LangGraph

Threat Intelligence is a dedicated stage in the LangGraph workflow.

```text
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
```

This ensures that external reputation evidence is available before the Investigation Agent produces its assessment.

---

## 21. Threat Intelligence Normalization

External providers return different response structures.

The backend therefore converts provider-specific responses into normalized internal results.

Conceptually:

```text
AbuseIPDB Response ----+
                       |
VirusTotal Response ---+--> Normalization --> Investigation Context
                       |
OTX Response ----------+
                       |
MISP Response ---------+
```

This reduces coupling between the investigation logic and external provider schemas.

---

## 22. Redis Cache

Threat Intelligence lookups can involve external API calls.

Repeatedly querying providers for the same indicator can:

- increase latency
- consume provider quotas
- trigger rate limits
- create unnecessary external traffic

The platform therefore uses Redis to cache enrichment results.

---

## 23. Redis Configuration

The backend uses:

```env
REDIS_URL=redis://redis:6379/0
```

inside the Docker Compose environment.

For local execution outside Docker, the default can be:

```env
REDIS_URL=redis://localhost:6379/0
```

---

## 24. Threat Intelligence Cache Keys

IP enrichment results use a cache key concept such as:

```text
soc:ti:ip:{ip}
```

For example:

```text
soc:ti:ip:8.8.8.8
```

The cached value contains normalized Threat Intelligence information.

---

## 25. Cache TTL

The implemented Threat Intelligence cache uses a TTL of:

```text
900 seconds
```

which corresponds to:

```text
15 minutes
```

After expiration, the next lookup can query the external providers again and refresh the cache.

---

## 26. Cache Flow

The enrichment flow is:

```text
Lookup Indicator
       |
       v
Check Redis
       |
   +---+---+
   |       |
  HIT     MISS
   |       |
   |       v
   |   Query Providers
   |       |
   |       v
   |   Normalize Result
   |       |
   |       v
   |   Store in Redis
   |       |
   +-------+
       |
       v
Return Enrichment
```

---

## 27. Redis Cache Validation

The cache behavior has been explicitly validated.

A representative test using:

```text
8.8.8.8
```

followed the sequence:

```text
CACHE MISS
     |
     v
External Providers
     |
     v
CACHE SET
     |
     v
Second Request
     |
     v
CACHE HIT
```

During validation, provider calls were made unavailable after the cached result was created.

The subsequent lookup still succeeded from Redis.

This confirms that the cache was actually used rather than simply configured.

---

## 28. Threat Intelligence Failure Handling

External Threat Intelligence providers may fail because of:

- timeout
- connectivity errors
- invalid credentials
- quota exhaustion
- provider outage
- rate limiting
- malformed provider responses

A provider failure should not automatically crash the entire SOC investigation.

The backend uses controlled error handling and avoids exposing raw internal exception details to clients.

---

# SOAR

## 29. SOAR Overview

Security Orchestration, Automation and Response manages actions proposed after incident investigation.

The prototype implements an internal SOAR module directly in the backend.

Its primary design principle is:

```text
Recommendation != Authorization != Execution
```

An AI recommendation alone is never sufficient to perform a sensitive action.

---

## 30. SOAR Architecture

The internal SOAR workflow can be represented as:

```text
Incident Investigation
        |
        v
Response Recommendation
        |
        v
Create SOAR Action
        |
        v
Authorization / Approval
        |
   +----+----+
   |         |
Reject     Approve
   |         |
   v         v
Stopped   Execution Gate
             |
             v
       Safety Controls
             |
             v
          Dry Run
             |
             v
         Audit Log
```

---

## 31. Supported SOAR Actions

The internal backend supports response concepts including:

```text
create_ticket
block_ip
isolate_endpoint
disable_user
send_notification
```

Some actions can be considered sensitive or potentially disruptive and therefore require appropriate safety controls.

---

## 32. SOAR API

The backend exposes:

```http
GET  /soar
GET  /soar/{action_id}
POST /soar

POST /soar/{action_id}/approve
POST /soar/{action_id}/reject
POST /soar/{action_id}/execute

GET /soar/{action_id}/logs
```

These endpoints separate action creation, approval, rejection, execution, and auditing.

---

## 33. SOAR Action Lifecycle

A response action follows a controlled lifecycle.

Conceptually:

```text
Created
   |
   +--------> Rejected
   |
   v
Approved
   |
   v
Execution Requested
   |
   v
Safety Validation
   |
   v
Executed / Simulated
   |
   v
Audit Log
```

This prevents immediate execution at the moment an action is proposed.

---

## 34. Human-in-the-Loop

Human-in-the-Loop is integrated into the incident workflow for high-risk situations.

High or critical investigations can pause before continuing.

```text
High / Critical Incident
          |
          v
     LangGraph Interrupt
          |
          v
      Human Review
          |
     +----+----+
     |         |
   Reject    Approve
               |
               v
          Resume Workflow
```

The human analyst remains responsible for validating sensitive response paths.

---

## 35. Workflow Resume

An interrupted LangGraph workflow can be resumed through:

```http
POST /agents/resume/{thread_id}
```

The resume endpoint is restricted to administrative authorization in the current backend.

This prevents the AI layer from autonomously approving its own high-risk workflow.

---

## 36. SOAR Authorization

SOAR operations are protected using backend authentication and role-based authorization.

The platform distinguishes between actions that an analyst can request and actions requiring stronger administrative authorization.

Sensitive operations such as approval, rejection, and execution are controlled server-side.

---

## 37. Dry-Run Mode

The prototype uses:

```env
SOAR_EXECUTION_MODE=dry_run
```

Dry-run mode allows the platform to exercise response logic without applying destructive changes to real infrastructure.

This is appropriate for:

- academic demonstration
- prototype testing
- workflow validation
- safe development

---

## 38. Destructive Action Flags

Potentially disruptive actions are disabled by default.

Example configuration:

```env
SOAR_ENABLE_BLOCK_IP=false
SOAR_ENABLE_ISOLATE_ENDPOINT=false
```

Therefore the existence of an action implementation does not mean that destructive execution is enabled.

---

## 39. Defense in Depth for SOAR

SOAR safety does not rely on a single control.

The prototype uses multiple layers:

```text
Authentication
      |
      v
RBAC
      |
      v
Human Review
      |
      v
SOAR Approval
      |
      v
Execution Mode
      |
      v
Action Safety Flags
      |
      v
Input Validation
      |
      v
Audit Logging
```

This provides defense in depth around response operations.

---

## 40. Action Safety Validation

Sensitive actions require validation before execution.

Examples include validating:

```text
IP addresses
endpoint identifiers
user targets
action parameters
```

The goal is to prevent malformed or unsafe targets from being passed directly into response execution logic.

---

## 41. Audit Logging

SOAR lifecycle events are persisted for traceability.

Audit information can record events related to:

```text
action creation
approval
rejection
execution request
dry-run simulation
execution result
```

Audit logs are available through:

```http
GET /soar/{action_id}/logs
```

---

## 42. AI and SOAR Separation

The LLM may recommend an action such as:

```text
Block the suspicious source IP.
```

However, the real control flow remains:

```text
LLM Recommendation
       |
       v
Backend SOAR Action
       |
       v
Authorization
       |
       v
Human Approval
       |
       v
Safety Checks
       |
       v
Execution Policy
```

The LLM itself has no direct authority to bypass these controls.

---

## 43. Validated SOAR Tests

The SOAR implementation has dedicated automated tests.

The validated SOAR test suite includes:

```text
tests/test_soar_service.py
tests/test_soar_executor.py
```

The latest focused validation produced:

```text
7 passed
```

This validates the internal SOAR service and execution safety behavior.

---

## 44. End-to-End SOAR Integration

A representative end-to-end incident workflow produced:

```text
AI Analysis
SOC Report
SOAR Action
```

The workflow included:

```text
Triage
Machine Learning
Threat Intelligence
Investigation
Human Review
Response
Report
```

This confirms that SOAR action generation is connected to the wider SOC workflow rather than existing only as an isolated CRUD module.

---

## 45. Representative HITL Flow

A representative incident reached:

```text
waiting_for_human
```

The workflow was then resumed by an authorized administrator.

After human validation, processing continued through:

```text
Response
Report
```

This validates the LangGraph interrupt/resume Human-in-the-Loop mechanism.

---

## 46. Shuffle Status

Shuffle is a third-party SOAR platform considered in the original project architecture.

However, Shuffle is not integrated into the current main Docker Compose prototype.

The main project stack does not currently contain an active Shuffle service.

Therefore the project must not claim:

```text
Shuffle integration completed
```

The accurate description is:

> The prototype implements and validates an internal SOAR workflow. Shuffle was considered and partially evaluated separately, but it is not integrated into the current main project stack.

---

## 47. Why Internal SOAR Is Used

The internal SOAR implementation allows the prototype to demonstrate core response orchestration concepts without depending on an external orchestration platform.

It demonstrates:

- action lifecycle management
- RBAC
- approval and rejection
- safe execution controls
- dry-run simulation
- auditability
- integration with the AI workflow
- Human-in-the-Loop

A future version could connect these controlled actions to an external SOAR platform.

---

## 48. Threat Intelligence and SOAR Relationship

Threat Intelligence provides evidence.

SOAR provides response orchestration.

They must remain logically separate.

```text
Indicator
   |
   v
Threat Intelligence
   |
   v
Evidence
   |
   v
Investigation
   |
   v
Risk Assessment
   |
   v
Human Review
   |
   v
SOAR
```

A malicious reputation result does not automatically trigger a destructive action.

---

## 49. Example Security Flow

A representative flow can be:

```text
Suspicious Source IP
        |
        v
Incident Created
        |
        v
Threat Intelligence
        |
        +---- AbuseIPDB
        +---- VirusTotal
        +---- OTX
        |
        v
Normalized Reputation Evidence
        |
        v
Investigation Agent
        |
        v
Risk Assessment
        |
        v
Response Recommendation
        |
        v
Human Approval
        |
        v
SOAR Action
        |
        v
Dry-Run Execution
        |
        v
Audit Log
```

---

## 50. Secret Management

Threat Intelligence API credentials must never be committed to Git.

Sensitive variables include:

```text
ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
OTX_API_KEY
MISP_API_KEY
```

In the validated prototype, the configured live provider secrets are available through the project's secret-management layer using HashiCorp Vault with environment/settings fallback.

MISP is not configured in the current environment.

---

## 51. Redis Security Considerations

Redis is an internal infrastructure component.

It stores temporary cached Threat Intelligence results.

The cache should not be considered a permanent source of truth.

In a production deployment, Redis should be protected through controls such as:

- network isolation
- authentication where appropriate
- restricted service access
- secure deployment configuration
- monitoring

---

## 52. Provider Trust Considerations

Threat Intelligence results are external evidence.

The platform must not assume that every provider result is perfectly accurate.

Possible issues include:

- false positives
- stale reputation
- missing observations
- conflicting providers
- incomplete context

The Investigation Agent should interpret provider evidence together with local telemetry, ML results, correlation, RAG knowledge, and human judgment.

---

## 53. Current Threat Intelligence Status

The current validated state is:

```text
AbuseIPDB       -> Implemented and live validated
VirusTotal      -> Implemented and live validated
AlienVault OTX -> Implemented and live validated
MISP            -> Implemented but not configured

Redis cache     -> Implemented and validated
Cache TTL       -> 900 seconds
Incident TI     -> Implemented
LangGraph TI    -> Integrated
```

---

## 54. Current SOAR Status

The current validated state is:

```text
Internal SOAR             -> Implemented
Action CRUD               -> Implemented
Approval / rejection      -> Implemented
Execution endpoint        -> Implemented
Audit logging             -> Implemented
Human-in-the-Loop         -> Implemented
LangGraph interrupt       -> Implemented
Admin resume              -> Implemented
Dry-run mode              -> Enabled
Real IP blocking          -> Disabled by default
Real endpoint isolation   -> Disabled by default
Shuffle integration       -> Not integrated
```

---

## 55. Current Prototype Safety Posture

The prototype intentionally prioritizes safe demonstration over autonomous destructive execution.

Default behavior is based on:

```text
AI recommends
      |
      v
Backend validates
      |
      v
Human approves
      |
      v
SOAR evaluates
      |
      v
Dry-run simulates
      |
      v
Audit records
```

This design keeps the SOC analyst in control of security-sensitive operations.

---

## 56. Future Improvements

Possible future extensions include:

- activate a dedicated MISP instance
- additional Threat Intelligence providers
- domain/URL/hash multi-provider aggregation
- provider confidence scoring
- improved cache invalidation
- asynchronous enrichment
- provider fallback strategies
- real firewall integration
- real endpoint isolation integration
- ticketing platform integration
- notification platform integration
- external Shuffle integration
- richer SOAR playbooks
- response rollback mechanisms

These are future improvements and are not claimed as implemented functionality.

---

## 57. Threat Intelligence and SOAR Summary

The implemented design follows:

```text
               Security Incident
                      |
                      v
             Threat Intelligence
              /      |       \
             /       |        \
            v        v         v
       AbuseIPDB VirusTotal   OTX
            \        |         /
             \       |        /
              +------+-------+
                     |
                     v
                 Redis Cache
                     |
                     v
                Investigation
                     |
                     v
               Risk Assessment
                     |
                     v
                Human Review
                     |
                     v
               Internal SOAR
                     |
                     v
               Safety Controls
                     |
                     v
                  Dry Run
                     |
                     v
                 Audit Log
```

Threat Intelligence enriches investigation with external evidence, while SOAR provides controlled response orchestration.

The prototype does not allow external reputation services or AI-generated recommendations to bypass authentication, RBAC, Human-in-the-Loop approval, SOAR execution policy, or audit controls.