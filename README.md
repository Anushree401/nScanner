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

## 💻 How to Run Guide (FastAPI)

## 1\. Start a New Scan (`POST /api/scan`)

This command sends the host and port list to the API, queuing the scan job and returning a unique **`scan_id`**.

| Detail | Value |
| :--- | :--- |
| **Method** | `POST` |
| **URL** | `http://127.0.0.1:8000/api/scan` |
| **Target** | `scanme.nmap.org` (Example) |

### Curl Command

Use the `-X POST` flag, set the content type header, and pass the data via `--data`.

```bash
# Execute this command in your terminal
curl -X POST "http://127.0.0.1:8000/api/scan" \
    -H "Content-Type: application/json" \
    -d '{"host": "scanme.nmap.org", "ports": "22,80,443"}'
```

**Example Output (JSON):**

```json
{
  "scan_id": "a3b4c5d6-e7f8-9a0b-c1d2-e3f4g5h6i7j8",
  "status": "queued",
  "message": "Scan initiated for scanme.nmap.org"
}
```

> **🔑 Actionable Tip:** If you have `jq` installed, you can extract the ID immediately by piping the output:
>
> ```bash
> scanId=$(curl -s -X POST "http://127.0.0.1:8000/api/scan" -H "Content-Type: application/json" -d '{"host": "scanme.nmap.org", "ports": "22,80,443"}' | jq -r '.scan_id')
> echo $scanId
> ```

-----

## 2\. Retrieve Scan Results (`GET /api/scan/{scan_id}`)

Use the `scan_id` obtained in the previous step to check the status or retrieve the final results. You will need to run this command repeatedly until the `status` changes to `"done"`.

| Detail | Value |
| :--- | :--- |
| **Method** | `GET` |
| **URL** | `http://127.0.0.1:8000/api/scan/{scan_id}` |

### Curl Command

Replace `YOUR_SCAN_ID` with the ID obtained from the POST response.

```bash
# Replace YOUR_SCAN_ID (e.g., 'a3b4c5d6-e7f8-9a0b-c1d2-e3f4g5h6i7j8')
curl -X GET "http://127.0.0.1:8000/api/scan/YOUR_SCAN_ID"
```

**Expected Final Output (JSON):**
When the scan is complete, the `status` will be `"done"`, and the full result will be printed:

```json
{
  "scan_id": "...",
  "host": "scanme.nmap.org",
  "ports": "22,80,443",
  "status": "done",
  "ports_scanned": 3,
  "open_ports": 2,
  "closed_ports": 1,
  "error_count": 0,
  "elapsed": 1.23,
  "risk_score": 45,
  "risk_level": "MEDIUM",
  "total_findings": 5,
  "critical_findings": 0,
  "high_findings": 1,
  "results": [
    {
      "host": "scanme.nmap.org",
      "port": 22,
      "state": "open",
      "service": "ssh",
      "banner": "...",
      "findings": [...],
      "mapping_summary": "...",
      "remediation": "...",
      "base_severity": "low"
    }
    // ... other ports ...
  ]
}
```

### PowerShell Note

For users on Windows PowerShell, the equivalent command is `Invoke-RestMethod` (as shown in the previous explanation):

```powershell
# Get status (PowerShell equivalent to curl -X GET)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/scan/YOUR_SCAN_ID" -Method Get
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
      * **Refer to above section for details**

-----

## 📄 License

This project is under a **Restricted Educational Use License**.

-----

## 🙋‍♀️ Author

**Anushree Balaji**

📧 [anushree1606balaji@gmail.com](mailto:anushree1606balaji@gmail.com)
🔗 [GitHub – Anushree401](https://github.com/Anushree401)
