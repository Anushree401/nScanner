import requests, os
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

url = "https://generativelanguage.googleapis.com/v1beta/models"

resp = requests.get(
    f"{url}?key={API_KEY}",
    headers={"Content-Type": "application/json"}
)

print(resp.status_code)
print(resp.text)
