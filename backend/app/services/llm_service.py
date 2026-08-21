import json

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
You are a SOC cybersecurity analyst.

Analyze the following cybersecurity incident.

Title: {title}
Description: {description}
Severity: {severity}
Source: {source}

Return ONLY a valid JSON object with exactly these fields:

{{
  "summary": "short summary of the incident",
  "risk_level": "low|medium|high|critical",
  "explanation": "technical explanation of the incident",
  "recommendation": "recommended remediation actions",
  "mitre_technique": "MITRE ATT&CK technique ID and name"
}}
"""

        response = self.client.chat.completions.create(
            model=settings.LLM_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        return json.loads(content)