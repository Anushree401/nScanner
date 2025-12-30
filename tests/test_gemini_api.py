import requests, os
from dotenv import load_dotenv
load_dotenv()

url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
key = os.getenv("GEMINI_API_KEY")

r = requests.post(
    f"{url}?key={key}",
    headers={"Content-Type": "application/json"},
    json={
        "contents": [{"parts": [{"text": "Return JSON: {\"ok\": true}"}]}]
    }
)

print(r.status_code)
print(r.text)
