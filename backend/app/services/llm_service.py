import json
import re
from typing import Optional

from openai import OpenAI, RateLimitError

from app.core.config import settings


class LLMService:

    def __init__(self):
        self.client = OpenAI(
            api_key=settings.GROQ_API_KEY,
            base_url=settings.LLM_BASE_URL,
        )

    def analyze_incident(
        self,
        title: str,
        description: str,
        severity: str,
        source: str,
        threat_intelligence: Optional[list[dict]] = None,
        rag_context: Optional[list[dict]] = None,
    ) -> dict:

        # =====================================================
        # 1. THREAT INTELLIGENCE CONTEXT
        # =====================================================

        if threat_intelligence:
            threat_context = json.dumps(
                threat_intelligence,
                indent=2,
            )
        else:
            threat_context = (
                "No threat intelligence data available."
            )

        # =====================================================
        # 2. RAG CONTEXT
        # =====================================================

        if rag_context:
            rag_text = json.dumps(
                rag_context,
                indent=2,
            )
        else:
            rag_text = (
                "No SOC playbook or knowledge base "
                "context available."
            )

        # =====================================================
        # 3. PROMPT
        # =====================================================

        prompt = f"""
You are an expert SOC cybersecurity analyst.

Analyze the following cybersecurity incident.

INCIDENT

Title: {title}
Description: {description}
Severity: {severity}
Source: {source}


THREAT INTELLIGENCE

The following information comes from external
threat intelligence sources such as AbuseIPDB:

{threat_context}


SOC KNOWLEDGE BASE / PLAYBOOKS

The following information comes from internal
SOC playbooks and incident response procedures:

{rag_text}


ANALYSIS RULES

Use all available evidence:

1. Incident information.
2. Threat intelligence.
3. SOC knowledge base and playbooks.

Important considerations:

- A high abuse score increases suspicion.
- A known Tor IP increases suspicion.
- A low abuse score does not prove that an incident is harmless.
- Distinguish IP reputation from observed malicious behavior.
- If a legitimate IP shows suspicious behavior, consider spoofing,
  proxying, NAT, logging errors, or compromised infrastructure.
- Use the SOC playbook to guide the investigation.
- Do not blindly copy the playbook.
- Adapt recommendations to the actual incident.
- Prefer evidence-based conclusions.
- Use a valid MITRE ATT&CK technique when possible.

IMPORTANT OUTPUT RULES

- Return exactly ONE complete JSON object.
- Never use placeholders such as "...".
- Never omit a required field.
- risk_level MUST be exactly one of:
  "low", "medium", "high", "critical".
- mitre_technique should contain a valid MITRE ATT&CK
  technique ID and name whenever applicable.
- Every value must be complete and meaningful.

OUTPUT FORMAT

Return exactly ONE JSON object containing these five keys:

summary
risk_level
explanation
recommendation
mitre_technique

Rules:

- summary must contain a real summary of THIS incident.
- explanation must contain a real technical analysis of THIS incident.
- recommendation must contain concrete actions for THIS incident.
- risk_level must be exactly:
  low, medium, high, or critical.
- mitre_technique must use the format:
  TXXXX - Technique Name

Never copy instructions into the values.

Never return placeholder values such as:
- "..."
- "summary"
- "short incident summary"
- "complete short incident summary"
- "technical explanation"
- "complete technical explanation"
- "recommended remediation actions"
- "complete remediation actions adapted to the incident"

Return JSON only.
"""

        # =====================================================
        # 4. CALL LLM
        # =====================================================

        try:
            response = self.client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a SOC cybersecurity analyst. "
                            "Use incident evidence, threat intelligence "
                            "and SOC knowledge base context. "
                            "Return only one complete JSON object."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                temperature=0.1,
            )

        except RateLimitError as exc:
            # -------------------------------------------------
            # GROQ / LLM RATE LIMIT
            # -------------------------------------------------
            #
            # Do not automatically retry here.
            #
            # A daily token limit may require waiting several
            # minutes. Automatic retries could consume more
            # tokens and keep the FastAPI request blocked.
            # -------------------------------------------------

            retry_after = None

            response_obj = getattr(
                exc,
                "response",
                None,
            )

            if response_obj is not None:
                headers = getattr(
                    response_obj,
                    "headers",
                    {},
                )

                if headers:
                    retry_after = headers.get(
                        "retry-after"
                    )

            message = (
                "LLM_RATE_LIMITED: Groq token limit reached."
            )

            if retry_after:
                message += (
                    f" Retry after approximately "
                    f"{retry_after} seconds."
                )

            raise RuntimeError(
                message
            ) from exc

        except Exception as exc:
            raise RuntimeError(
                f"LLM_REQUEST_FAILED: {exc}"
            ) from exc

        # =====================================================
        # 5. GET RESPONSE CONTENT
        # =====================================================

        content = response.choices[0].message.content

        if not content:
            raise ValueError(
                "LLM returned an empty response"
            )

        content = content.strip()

        # Remove Markdown blocks if the model adds them.
        content = re.sub(
            r"```json\s*",
            "",
            content,
            flags=re.IGNORECASE,
        )

        content = content.replace(
            "```",
            "",
        )

        # =====================================================
        # 6. EXTRACT VALID JSON
        # =====================================================

        decoder = json.JSONDecoder()
        valid_objects = []

        for index, char in enumerate(content):

            if char != "{":
                continue

            try:
                obj, _ = decoder.raw_decode(
                    content[index:]
                )

                if isinstance(obj, dict):
                    valid_objects.append(obj)

            except json.JSONDecodeError:
                continue

        if not valid_objects:
            raise ValueError(
                "No valid JSON object found in LLM response"
            )

        # =====================================================
        # 7. VALIDATE REQUIRED FIELDS
        # =====================================================

        required_fields = {
            "summary",
            "risk_level",
            "explanation",
            "recommendation",
            "mitre_technique",
        }

        result = None

        for obj in reversed(valid_objects):

            if required_fields.issubset(
                obj.keys()
            ):
                result = obj
                break

        if result is None:
            raise ValueError(
                "LLM JSON is missing required fields"
            )

        # =====================================================
        # 8. NORMALIZE RISK LEVEL
        # =====================================================

        allowed_risks = {
            "low",
            "medium",
            "high",
            "critical",
        }

        risk = str(
            result.get(
                "risk_level",
                "",
            )
        ).lower().strip()

        risk_mapping = {
            "info": "low",
            "informational": "low",
            "minimal": "low",

            "moderate": "medium",
            "moderated": "medium",

            "severe": "high",
            "serious": "high",

            "very high": "critical",
            "very_high": "critical",
            "very-high": "critical",
        }

        risk = risk_mapping.get(
            risk,
            risk,
        )

        # =====================================================
        # 9. FALLBACK IF INVALID
        # =====================================================

        if risk not in allowed_risks:

            incident_severity = str(
                severity
            ).lower().strip()

            incident_severity = risk_mapping.get(
                incident_severity,
                incident_severity,
            )

            if incident_severity in allowed_risks:
                risk = incident_severity
            else:
                risk = "medium"

        result["risk_level"] = risk

        # =====================================================
        # 10. CLEAN AND VALIDATE TEXT FIELDS
        # =====================================================

        text_fields = [
            "summary",
            "explanation",
            "recommendation",
            "mitre_technique",
        ]

        for field in text_fields:

            value = result.get(field)

            if value is None:
                result[field] = ""
            else:
                result[field] = str(
                    value
                ).strip()

        invalid_placeholders = {
            "",
            "...",
            "summary",
            "short incident summary",
            "complete short incident summary",
            "technical explanation",
            "complete technical explanation",
            (
                "complete technical explanation combining "
                "incident evidence, threat intelligence "
                "and soc knowledge"
            ),
            "recommended remediation actions",
            "complete remediation actions adapted to the incident",
        }

        # =====================================================
        # 11. SUMMARY FALLBACK
        # =====================================================

        if result["summary"].lower() in invalid_placeholders:
            result["summary"] = (
                f"Suspicious security activity was detected: "
                f"{title}. {description}"
            )

        # =====================================================
        # 12. EXPLANATION FALLBACK
        # =====================================================

        if result["explanation"].lower() in invalid_placeholders:

            if threat_intelligence:
                result["explanation"] = (
                    "The incident shows suspicious activity that "
                    "requires investigation. Threat intelligence "
                    "data was reviewed together with the observed "
                    "security behavior. The reputation of an IP "
                    "address alone is not sufficient to determine "
                    "whether the incident is benign."
                )
            else:
                result["explanation"] = (
                    "The incident contains suspicious activity "
                    "that requires further investigation using "
                    "authentication, network and security logs."
                )

        # =====================================================
        # 13. RECOMMENDATION FALLBACK
        # =====================================================

        if result["recommendation"].lower() in invalid_placeholders:
            result["recommendation"] = (
                "Review authentication logs, network flows and "
                "firewall logs. Validate the real source of the "
                "activity before blocking an IP or executing "
                "containment actions."
            )

        # =====================================================
        # 14. MITRE FALLBACK
        # =====================================================

        if result["mitre_technique"].lower() in invalid_placeholders:

            incident_text = (
                f"{title} {description}"
            ).lower()

            if (
                "failed login" in incident_text
                or "login attempts" in incident_text
                or "brute force" in incident_text
            ):
                result["mitre_technique"] = (
                    "T1110 - Brute Force"
                )

            elif (
                "port scan" in incident_text
                or "network scan" in incident_text
                or "nmap" in incident_text
            ):
                result["mitre_technique"] = (
                    "T1046 - Network Service Discovery"
                )

            else:
                result["mitre_technique"] = ""

        # =====================================================
        # 15. RETURN
        # =====================================================

        return result