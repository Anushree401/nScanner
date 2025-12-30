# 🔐 Security Policy

## Supported Versions

nScanner is currently under active development. Security fixes are applied only to the latest development versions.

| Version           | Supported |
| ----------------- | --------- |
| `main` / `latest` | ✅         |
| Older releases    | ❌         |

> ⚠️ This project is evolving rapidly. Users are strongly encouraged to run the latest version to receive security fixes.

---

## Reporting a Vulnerability

If you discover a security vulnerability in **nScanner**, please report it responsibly.

### ✅ How to report

* **Do NOT** create a public GitHub issue for security vulnerabilities.
* Instead, report it via:

  * **GitHub Security Advisories** (preferred), or
  * A **private email** to the project maintainer.

### 📬 Contact

* GitHub Security Advisory:
  `Repository → Security → Report a vulnerability`
* Email:
  `anushree1606balaji@gmail.com`
  
---

## What to include in your report

Please include as much detail as possible:

* Description of the vulnerability
* Steps to reproduce
* Affected endpoints / components
* Potential impact
* Proof-of-concept (if available)

---

## Response timeline

* **Initial acknowledgment**: within **48–72 hours**
* **Status updates**: provided as the issue is investigated
* **Fix & disclosure**: coordinated responsibly once validated

---

## Scope

This security policy applies to:

* Backend APIs
* Database handling
* Authentication & authorization logic
* Dependency usage
* Secret management
* Configuration and deployment-related issues

---

## Out of scope

The following are generally considered out of scope:

* Denial-of-service attacks via large scans
* Social engineering attacks
* Vulnerabilities in third-party services unless directly caused by nScanner

---

## Responsible Disclosure

We appreciate responsible disclosure and will credit researchers when appropriate.

---

## 🔎 Notes for Contributors

* **Never commit secrets** (API keys, tokens, credentials)
* Use environment variables for all sensitive configuration
* Database files (`*.db`) must not be committed
* Follow secure coding practices and least-privilege principles
