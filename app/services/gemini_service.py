import os 
import json 
import requests 
from dotenv import load_dotenv
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/"
    "models/gemini-2.5-flash:generateContent"
)

def summarize_with_gemini(scan_results:dict,risk_summary:dict) -> dict:
    """
    Send scan results to Gemini and get AI-enhanced summary.
    """
    
    prompt = f"""
    You are a cybersecurity analyst.

    IMPORTANT:
    - Respond with ONLY valid JSON
    - Do NOT use markdown
    - Do NOT wrap response in ```json
    - Do NOT add commentary

    JSON schema:
    {{
    "executive_summary": string,
    "key_findings": list,
    "attack_surface_overview": string,
    "risk_level": string,
    "recommendations": list
    }}

    Scan Results:
    {json.dumps(scan_results, indent=2)}

    Risk Summary:
    {json.dumps(risk_summary, indent=2)}
    """
    
    response = requests.post(
        f"{GEMINI_URL}?key={GEMINI_API_KEY}",
        headers={"Content-Type": "application/json"},
        json={
            "contents": [
                {
                    "parts": [{"text":prompt}]
                }
            ]
        },
        timeout=30
    )
    
    response.raise_for_status()
    data = response.json()
    
    # here
    text = (
        data.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text", "")
    )

    text = text.strip()

    if text.startswith("```"):
        text = (
            text.replace("```json", "")
                .replace("```", "")
                .strip()
        )

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print("Gemini raw output:\n", text)
        raise

