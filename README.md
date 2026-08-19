# 🛡️ AI Application Security Auditor & Remediation Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/Node.js-v20+-green.svg)](https://nodejs.org)
[![OS Support](https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows-brightgreen.svg)]()
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker)]()

An enterprise-grade, **Linux-native Application Security (AppSec) and Red Team Adversary Simulation Platform**. The system provides end-to-end security automation across static code analysis, software composition, secret detection, DAST network probing, autonomous exploit proof validation, AI-guided root cause remediation, and automated sandbox fix verification.

---

## 🚀 Core Philosophy: Find → Explain → Prioritize → Recommend → Fix → Test → Verify

Most vulnerability scanners stop at *"you have a vulnerability."* This platform takes security from identification through verified resolution:
1. **Find**: Multi-engine static, dynamic, dependency, secret, and configuration inspection.
2. **Explain**: AI Security Analyst breaks down the attack vectors, root causes, and business impact.
3. **Prioritize**: Threat correlation and kill chain synthesis filter noise and highlight critical attack paths.
4. **Recommend & Fix**: Generates contextual, ready-to-apply code patches and configuration changes.
5. **Test & Verify**: Applies the patch inside an isolated sandbox, re-runs automated assertions and rescans to prove the vulnerability is resolved.

---

## 🏛️ Platform Architecture

```
                               ┌──────────────────────────────┐
                               │        WEB DASHBOARD         │
                               │  (Next.js / React + Tailwind)│
                               └──────────────┬───────────────┘
                                              │
                                              ▼
                               ┌──────────────────────────────┐
                               │      EXPRESS API GATEWAY     │
                               │   (Node.js + REST Endpoints) │
                               └──────────────┬───────────────┘
                                              │
               ┌──────────────────────────────┴──────────────────────────────┐
               │                                                             │
               ▼                                                             ▼
    ┌─────────────────────────────┐                           ┌──────────────────────────────┐
    │  APPLICATION SECURITY ENGINE│                           │       RED TEAM ENGINE        │
    │  - SAST (Semgrep, Bandit)   │                           │  - Scope & Authorization     │
    │  - SCA (OSV.dev, pip-audit) │                           │  - Deep Reconnaissance       │
    │  - Secrets (Gitleaks)       │                           │  - Multi-Node Attack Graphs  │
    │  - DAST & Recon (Nmap, TLS) │                           │  - Controlled Exploit Probes │
    │  - Container (Trivy)        │                           │  - Purple Team Defense Audit │
    └──────────────┬──────────────┘                           └──────────────┬───────────────┘
                   │                                                         │
                   └──────────────────────────┬──────────────────────────────┘
                                              │
                                              ▼
                               ┌──────────────────────────────┐
                               │     SECURITY CORRELATION     │
                               │ (Vulnerability + Evidence)   │
                               └──────────────┬───────────────┘
                                              │
                                              ▼
                               ┌──────────────────────────────┐
                               │     AI SECURITY ANALYST      │
                               │  (Google Gemini 2.5 Pro/Flash)│
                               └──────────────┬───────────────┘
                                              │
                                              ▼
                               ┌──────────────────────────────┐
                               │      REMEDIATION ENGINE      │
                               │  (Unified Diff Patch Synth)  │
                               └──────────────┬───────────────┘
                                              │
                                              ▼
                               ┌──────────────────────────────┐
                               │     VERIFICATION ENGINE      │
                               │  (Sandbox Re-test & Rescan)  │
                               └──────────────────────────────┘
```

---

## ⚙️ Key Subsystems & Features

### 1. 🔍 Comprehensive Application Security Scanner
- **SAST (Static Application Security Testing)**: Orchestrates `semgrep` and `bandit` across JavaScript, TypeScript, Python, Java, Go, PHP, C#, Ruby, Swift, and C++.
- **SCA (Software Composition Analysis)**: Real-time queries to **OSV.dev API** batch endpoints and `pip-audit` / `npm audit` for zero-mock dependency CVE identification.
- **Secret & Credential Discovery**: `gitleaks` CLI integration detecting exposed AWS keys, Stripe tokens, JWT secrets, DB URIs, and private keys.
- **DAST & Network Reconnaissance**: Real `nmap` execution supporting Quick Discovery, Comprehensive Audit, and Vulnerability NSE scripts (`http-vuln*`, `http-headers`, `http-cors`).
- **Live HTTP & SSL/TLS Header Auditor**: Audits live certificates, HSTS, CSP, X-Frame-Options, MIME sniffing, and CORS policies.
- **Mobile & Desktop Binary Audit**: Analyzes Android APK manifests/permissions, iOS Info.plist ATS settings, Windows PE ASLR/DEP headers, and macOS Hardened Runtimes.

### 2. ⚔️ Red Team & Purple Team Adversary Engine
- **Layer 1: Scope & Authorization Gateway**: Strictly bounds all simulation activities, generates cryptographic audit tokens, and enforces production database protection.
- **Layer 2: Reconnaissance Engine**: Discovers endpoints, API routing tables, authentication boundaries, and technology stacks.
- **Layer 3: Attack Planner & Attack Graphs**: Correlates isolated CVEs into multi-stage kill chains (e.g. *Ingress Recon → Auth Bypass → Privilege Escalation → Database Query Sink → Exfiltration*).
- **Layer 4: Controlled Exploit Validation**: Safely proves exploitability in an isolated sandbox with synthetic data records (zero production risk).
- **Layer 5: Purple Team Defense Audits**: Benchmarks defensive detection effectiveness across WAF rules (OWASP ModSecurity CRS), IDS signatures (Emerging Threats), and SIEM logs.
- **Layer 6: AI Adversary Analyst**: Produces structured attack narratives, blast radius analyses, and prioritized 3-step remediations.

### 3. 🛠️ Remediation & Patch Verification Loop
- **Contextual Diff Synthesis**: Generates drop-in replacement unified diffs.
- **Automated Sandbox Execution**: Writes the patch to target AST, executes automated unit assertions, and performs an immediate rescan.
- **Cryptographic Proof of Resolution**: Confirms that the vulnerability is gone and marks finding as `VERIFIED_RESOLVED`.

---

## 🚀 Quick Start & Installation

### Option A: Run Natively on Linux

#### 1. Clone the repository
```bash
git clone https://github.com/stephanas-code/AI-Application-Security-Auditor-Platform.git
cd AI-Application-Security-Auditor-Platform
```

#### 2. Run the Linux AppSec Tools Installer
This installer configures `nmap`, `semgrep`, `gitleaks`, `trivy`, `bandit`, `pip-audit`, and `python3`:
```bash
chmod +x setup_linux.sh
./setup_linux.sh
```

#### 3. Configure Environment Variables
```bash
cp .env.example .env
```
Edit `.env` and configure your `GEMINI_API_KEY`:
```env
GEMINI_API_KEY="your_api_key_here"
PORT=3000
```

#### 4. Install Node Dependencies & Run
```bash
npm install
npm run dev
```
Open **`http://localhost:3000`** in your browser.

---

### Option B: Run via Docker (All Tools Bundled)

Run the platform inside an isolated container with all Linux security tools pre-installed:

```bash
docker compose up -d --build
```
Access the dashboard at **`http://localhost:3000`**.

To stop the container:
```bash
docker compose down
```

---

## 📋 API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/tools/status` | `GET` | System diagnostic returning availability, path, and version of `nmap`, `semgrep`, `gitleaks`, `trivy`, `bandit`, `docker`, and `git`. |
| `/api/intake/git` | `POST` | Clones remote Git repositories into isolated temporary workspaces and extracts code files. |
| `/api/intake/local-dir` | `POST` | Ingests and indexes any local Linux directory on the host (e.g. `/var/www/app`). |
| `/api/scan/dast/nmap` | `POST` | Executes real `nmap` network and port discovery with customizable NSE profiles. |
| `/api/scan/dast/http-probe` | `POST` | Performs live HTTP/TLS probing, SSL certificate audits, and security header checks. |
| `/api/scan/multi-engine` | `POST` | Orchestrates `semgrep` and `gitleaks` CLI binaries on target codebases. |
| `/api/redteam/simulate` | `POST` | Executes the 6-layer adversary simulation, attack graph synthesis, and Purple Team audits. |
| `/api/analyze` | `POST` | AI Security Analyst risk correlation and threat modeling. |
| `/api/generate-fix` | `POST` | AI remediation engine generating unified diff code patches. |
| `/api/verify-patch` | `POST` | Automated sandbox patch application, test runner, and rescan verification. |

---

## 🛡️ Supported Audit Frameworks
- **OWASP Top 10 (2021)**
- **NIST SP 800-53 Rev 5**
- **SOC 2 Type II (Trust Services Criteria)**
- **ISO/IEC 27001:2022**
- **PCI-DSS v4.0**
- **HIPAA Security Rule**

---

## 📜 License
This project is licensed under the **MIT License**.
