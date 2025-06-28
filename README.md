````markdown
# 🔍 NScanner - Web-Based Threat Scanner

NScanner is a lightweight, Flask-powered web application that allows users to perform **active port scanning** and **passive reconnaissance** on IP addresses or domain names. It's designed as a simple, educational InfoSec tool for network visibility and analysis.

---

## ⚙️ Features

### ✅ Active Scan
- Uses **Nmap** to scan for open TCP ports
- Supports:
  - Port ranges (e.g., `20-25`)
  - Comma-separated ports (e.g., `80,443`)
  - Verbose mode for filtered/closed ports

### ✅ Passive Reconnaissance
- Retrieves:
  - **IP address** of the domain
  - **HTTP headers** via HTTPS
  - **IP geolocation & ISP info** using `ipinfo.io`
  - **WHOIS data** using `ipwhois`

### ✅ Web Interface
- Clean, responsive UI (HTML + CSS)
- Easy to deploy on platforms like **Render**, **Replit**, or **Heroku**

---

## 📦 Dependencies

- Python 3.7+
- Flask
- Requests
- IPWhois
- python-nmap
- Colorama

Install via:
```bash
pip install -r requirements.txt
````

---

## 🚀 Running Locally

Clone and run:

```bash
git clone https://github.com/YOUR_USERNAME/nscanner.git
cd nscanner
python app.py
```

Then go to:

```
http://localhost:80
```

If you're using Render or another host that provides `$PORT`, change the run command in `app.py`:

```python
import os
port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)
```

---

## 🛡️ Legal Notice

This tool is intended for **educational and authorized use only**. Do **not** scan or probe devices or domains you don’t own or don’t have permission to test.

---

## 📁 Folder Structure

```
nscanner/
├── app.py                  # Main Flask app
├── scanner.py              # Scanning logic (active + passive)
├── templates/
│   └── scanner_index.html  # Jinja2 HTML template
├── static/
│   └── style.css           # Custom styles
├── requirements.txt
└── README.md
```

---

## ✨ Future Ideas

* Add banner grabbing
* Add DNS records lookup
* Export scan reports as PDF/JSON
* Add authentication for multi-user use

---

## 🛡 License

This project is licensed under a **custom restricted license**.  
It allows personal and academic use **with credit**, but **prohibits commercial use** without prior permission.

📄 [Read the full license here](LICENSE)

```
