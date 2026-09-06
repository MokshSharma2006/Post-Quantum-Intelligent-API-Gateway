import os
import json
from google import genai


class LLMThreatClassifier:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.enabled = bool(self.api_key)

        if self.enabled:
            self.client = genai.Client(api_key=self.api_key)

            self.model = os.getenv(
                "LLM_MODEL",
                "gemini-3.8-flash"
            )

            print("[LLM] Enabled")
            print(f"[LLM] Provider : Google Gemini")
            print(f"[LLM] Model    : {self.model}")

        else:
            self.client = None
            self.model = None

            print("[LLM] Gemini API key not configured")
            print("[LLM] Mode : DISABLED")

    def analyze(
        self,
        endpoint,
        method,
        client_ip,
        anomaly_score,
        threat_level,
        request_body=""
    ):

        if not self.enabled:
            return {
                "enabled": False,
                "provider": "gemini",
                "attack_type": "UNKNOWN",
                "severity": threat_level,
                "confidence": 0,
                "recommendation": "USE_ANOMALY_ENGINE",
                "explanation": "Gemini analysis is disabled"
            }

        # Do not send unlimited request data to the LLM.
        request_body = request_body[:2000]

        prompt = f"""
You are a cybersecurity threat analysis engine
inside an API security gateway.

Analyze the following API request metadata.

Endpoint:
{endpoint}

HTTP Method:
{method}

Client IP:
{client_ip}

Anomaly Score:
{anomaly_score}/100

Existing Threat Level:
{threat_level}

Request Body:
{request_body}

Determine whether this request is associated with
a cybersecurity attack.

Possible attack types include:

- DDoS
- Brute Force
- SQL Injection
- Command Injection
- Path Traversal
- API Abuse
- Credential Attack
- Reconnaissance
- Bot Activity
- Normal Traffic
- Unknown

Return ONLY valid JSON.

Use exactly this structure:

{{
    "attack_type": "DDoS|Brute Force|SQL Injection|Command Injection|Path Traversal|API Abuse|Credential Attack|Reconnaissance|Bot Activity|Normal Traffic|Unknown",
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "confidence": 0,
    "recommendation": "ALLOW|MONITOR|BLOCK",
    "explanation": "Short explanation"
}}

The confidence must be an integer from 0 to 100.

Do not include markdown.
Do not include ```json.
Do not include any text outside the JSON.
"""

        try:

            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )

            text = response.text.strip()

            # Remove accidental markdown fences
            if text.startswith("```"):
                text = text.replace("```json", "")
                text = text.replace("```", "")
                text = text.strip()

            result = json.loads(text)

            return {
                "enabled": True,
                "provider": "gemini",
                "attack_type": result.get(
                    "attack_type",
                    "Unknown"
                ),
                "severity": result.get(
                    "severity",
                    "MEDIUM"
                ),
                "confidence": int(
                    result.get("confidence", 0)
                ),
                "recommendation": result.get(
                    "recommendation",
                    "MONITOR"
                ),
                "explanation": result.get(
                    "explanation",
                    ""
                )
            }

        except Exception as e:

            print(f"[LLM ERROR] {e}")

            return {
                "enabled": True,
                "provider": "gemini",
                "attack_type": "UNKNOWN",
                "severity": "MEDIUM",
                "confidence": 0,
                "recommendation": "MONITOR",
                "explanation": "Gemini analysis failed"
            }