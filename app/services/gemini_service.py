import os 
import json 
import requests 

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/"
    "models/gemini-pro:generateContent"
)

def summarize_with_gemini(scan_results:dict,risk_summary:dict) -> dict:
    """
    Send scan results to Gemini and get AI-enhanced summary.
    """
    
    prompt = f"""
        You are a cybersecurity analyst.

        Given the following scan results and computed risk summary,
        produce a concise security report.

        Scan Results:
        {json.dumps(scan_results, indent=2)}

        Risk Summary:
        {json.dumps(risk_summary, indent=2)}

        Return STRICT JSON with keys:
        - executive_summary
        - key_findings
        - attack_surface_overview
        - risk_level
        - recommendations
    """
    
    response = requests.post(
        f"{GEMINI_URL}?key={GEMINI_API_KEY}",
        headers={"Content-type":"application/json"},
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
    
    text = (
        data.get("candidates",[{}])[0]
        .get("content",{})
        .get("parts",[{}])[0]
        .get("text","{}")
    )
    
    return json.loads(text)