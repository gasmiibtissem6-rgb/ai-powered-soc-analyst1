import json
import re
from typing import Optional

from openai import OpenAI

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
    ) -> dict:

        # Transformer Threat Intelligence en texte
        if threat_intelligence:
            threat_context = json.dumps(
                threat_intelligence,
                indent=2,
            )
        else:
            threat_context = "No threat intelligence data available."

        prompt = f"""
You are an expert SOC cybersecurity analyst.

Analyze the following cybersecurity incident.

INCIDENT
Title: {title}
Description: {description}
Severity: {severity}
Source: {source}

THREAT INTELLIGENCE
The following information comes from AbuseIPDB:

{threat_context}

Important:
Use the Threat Intelligence information when evaluating the incident.

For example:
- a high abuse score increases suspicion;
- a known Tor IP increases suspicion;
- a low abuse score does NOT prove that an incident is harmless;
- distinguish the reputation of the IP from the malicious behavior observed in the incident.

Return a JSON object containing exactly:

{{
  "summary": "short incident summary",
  "risk_level": "low|medium|high|critical",
  "explanation": "technical explanation combining incident evidence and threat intelligence",
  "recommendation": "recommended remediation actions",
  "mitre_technique": "TXXXX - Technique Name"
}}

Return only the JSON object.
"""

        response = self.client.chat.completions.create(
            model=settings.LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a SOC cybersecurity analyst. "
                        "Return only the final JSON object."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.1,
        )

        content = response.choices[0].message.content

        if not content:
            raise ValueError(
                "LLM returned an empty response"
            )

        content = content.strip()

        content = re.sub(
            r"```json\s*",
            "",
            content,
            flags=re.IGNORECASE,
        )

        content = content.replace("```", "")

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

        allowed_risks = {
            "low",
            "medium",
            "high",
            "critical",
        }

        risk = str(
            result["risk_level"]
        ).lower().strip()

        if risk not in allowed_risks:
            raise ValueError(
                f"Invalid risk level: {risk}"
            )

        result["risk_level"] = risk

        return result