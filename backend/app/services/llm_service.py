import json
import re

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
    ) -> dict:

        prompt = f"""
Analyze this cybersecurity incident as a SOC analyst.

Title: {title}
Description: {description}
Severity: {severity}
Source: {source}

Return a JSON object containing exactly:

{{
  "summary": "short incident summary",
  "risk_level": "low|medium|high|critical",
  "explanation": "technical explanation",
  "recommendation": "recommended remediation actions",
  "mitre_technique": "TXXXX - Technique Name"
}}

Return the JSON object only.
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
            raise ValueError("LLM returned an empty response")

        content = content.strip()

        # Supprimer les blocs Markdown éventuels
        content = re.sub(
            r"```json\s*",
            "",
            content,
            flags=re.IGNORECASE,
        )
        content = content.replace("```", "")

        # Chercher tous les objets JSON possibles
        decoder = json.JSONDecoder()

        valid_objects = []

        for index, char in enumerate(content):

            if char != "{":
                continue

            try:
                obj, end = decoder.raw_decode(
                    content[index:]
                )

                if isinstance(obj, dict):
                    valid_objects.append(obj)

            except json.JSONDecodeError:
                continue

        if not valid_objects:
            raise ValueError(
                f"No valid JSON object found in LLM response: {content}"
            )

        # Chercher un objet contenant les champs attendus
        required_fields = {
            "summary",
            "risk_level",
            "explanation",
            "recommendation",
            "mitre_technique",
        }

        result = None

        for obj in reversed(valid_objects):

            if required_fields.issubset(obj.keys()):
                result = obj
                break

        if result is None:
            raise ValueError(
                "LLM returned JSON but required fields are missing"
            )

        # Vérifier risk_level
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
                f"Invalid risk_level returned by LLM: {risk}"
            )

        result["risk_level"] = risk

        return result