# 🔍 nScanner – Safe, Web-Based Network Recon Tool

**nScanner** is a cybersecurity utility that performs **non-intrusive port scanning** and generates a risk assessment based on observed service banners and configurations. The core logic is built in Python, exposed via a high-performance **FastAPI** backend for a robust, scalable architecture.

> ⚠️ For educational and personal use only. Not for unauthorized or commercial use.

-----

## 🚀 Features

  * **FastAPI Backend:** Built on Python's FastAPI for asynchronous, high-speed, scalable performance.
  * **Safety-Focused Scanning:** Uses safe, non-exploitative TCP socket checks (not Nmap) to gather service banners, HTTP headers, and TLS certificate info.
  * **Risk Assessment:** Calculates a vulnerability risk score and level for scanned hosts.
  * **RESTful API:** All functionality is accessible via well-defined, documented REST endpoints.

-----

## 🧠 Prerequisites

  * Python 3.8+ (3.11/3.12 recommended for development)
  * **Local Setup:** A working Python virtual environment.

-----

## 💻 Local Setup Instructions (FastAPI)

These instructions set up the primary FastAPI web server.

1.  **Clone the repository**

    ```bash
    git clone https://github.com/Anushree401/nScanner.git
    cd nScanner
    ```

2.  **Create and activate virtual environment**

    ```bash
    python -m venv svenv
    .\svenv\Scripts\activate  # On Windows PowerShell
    # OR
    source svenv/bin/activate # On Linux/macOS
    ```

3.  **Install dependencies**
    The project uses concurrent processing and database management, so we need the production dependencies.

    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the FastAPI server**
    The application runs on port `8000` by default.

    ```bash
    uvicorn app.main:app --reload
    ```

-----

## 🐳 Run with Docker (Recommended for Deployment)

This uses the containerized environment, removing the need for local setup.

1.  **Build the Docker image**
    (The container runs the FastAPI app on port 8000).

    ```bash
    docker build -t nscanner .
    ```

2.  **Run the container**
    This maps host port 5000 to the container's internal port 8000.

    ```bash
    docker run -p 5000:8000 nscanner
    ```

-----

## 💡 Using the API Endpoints

The web user interface is currently under development. However, the core asynchronous scanning endpoints are fully functional and accessible through the interactive API documentation.

### The Endpoints are Working\!

You can begin running and analyzing scans immediately.

1.  **Access the Interactive Documentation (Swagger UI):**
    Open your browser to: **`http://127.0.0.1:8000/docs`** (or `http://localhost:5000/docs` if using the Docker setup).

2.  **How to Use:**

      * **Start a Scan (`POST /api/scan`):** Click "Try it out," enter the target host and ports (e.g., `"ports": "22,80,443"`), and click **Execute**. The response will contain a `scan_id`.
      * **Get Results (`GET /api/scan/{scan_id}`):** Use the `scan_id` from the previous step to poll this endpoint. The final response (`"status": "done"`) will contain the full scan results, risk score, and detailed findings.

-----

## 📄 License

This project is under a **Restricted Educational Use License**.

-----

## 🙋‍♀️ Author

**Anushree Balaji**

📧 [anushree1606balaji@gmail.com](mailto:anushree1606balaji@gmail.com)
🔗 [GitHub – Anushree401](https://github.com/Anushree401)