# app/main.py
"""
FastAPI application entry point for nScanner.

Run with: uvicorn app.main:app --reload
"""

from app.api.routes import app

# The app is imported from routes.py
# This file serves as the main entry point for uvicorn

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)