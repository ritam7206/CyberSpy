# 🛡️ CyberSpy AI

**A Lightweight Edge-AI Framework for Real-Time Anomaly Detection and Prevention in Heterogeneous IoT and Computer Networks**

> Final-year Computer Engineering major project.
> **Project status:** 🚧 In development, starting at Phase 1. See [Implementation Status](#-implementation-status) for what is built, simulated, and planned.

---

## 📑 Table of Contents

1. [Overview](#-overview)
2. [Important Disclaimers](#-important-disclaimers)
3. [Key Features](#-key-features)
4. [Implementation Status](#-implementation-status)
5. [System Architecture](#-system-architecture)
6. [Technology Stack](#-technology-stack)
7. [Project Structure](#-project-structure)
8. [Prerequisites](#-prerequisites)
9. [Installation (Windows 11)](#-installation-windows-11)
10. [Installation (Linux)](#-installation-linux)
11. [Configuration](#-configuration)
12. [Running the Application](#-running-the-application)
13. [Verifying the Installation](#-verifying-the-installation)
14. [Dashboard Pages](#-dashboard-pages)
15. [AI Anomaly Detection Pipeline](#-ai-anomaly-detection-pipeline)
16. [Risk Scoring](#-risk-scoring)
17. [Device Behaviour Drift Detection](#-device-behaviour-drift-detection)
18. [Response Policy Engine](#-response-policy-engine)
19. [Digital Twin](#-digital-twin)
20. [Firewall Integration and Safety Model](#-firewall-integration-and-safety-model)
21. [Database Design](#-database-design)
22. [Authentication and Authorization](#-authentication-and-authorization)
23. [API Overview](#-api-overview)
24. [Testing](#-testing)
25. [Security Considerations](#-security-considerations)
26. [Development Phases](#-development-phases)
27. [Known Limitations](#-known-limitations)
28. [Future Enhancements](#-future-enhancements)
29. [Troubleshooting](#-troubleshooting)
30. [Contributing and Conventions](#-contributing-and-conventions)
31. [Documentation Index](#-documentation-index)
32. [License and Acknowledgements](#-license-and-acknowledgements)

---

## 🔎 Overview

CyberSpy AI is an AI-assisted network security platform. It watches network behaviour, learns what is normal for each device, flags unusual activity, scores the risk, and **recommends** a response. A human administrator stays in control of every sensitive action.

In simple terms:

1. **Agents** collect traffic information from Windows/Linux machines.
2. A **backend** stores the data and runs a machine-learning model (Isolation Forest) to spot unusual behaviour.
3. A **risk engine** turns anomalies into understandable alerts.
4. A **digital twin** simulates what a proposed firewall rule would break *before* it is applied.
5. An authorized **administrator approves** the action.
6. A **firewall agent** applies the rule safely, **verifies** it, and writes an **audit log**.
7. A **React dashboard** shows everything in one place.

### Project Objectives

1. Detect unusual network traffic in near real time.
2. Learn behavioural baselines for different devices.
3. Identify suspicious changes in device behaviour.
4. Display understandable security alerts.
5. Calculate a risk score for suspicious events.
6. Simulate proposed security actions using a digital twin.
7. Integrate with Windows Firewall and Linux firewalls (nftables).
8. Require authorization before sensitive actions.
9. Verify firewall actions and maintain an audit trail.
10. Minimize disruption to legitimate traffic.
11. Support lightweight execution on edge computers.
12. Provide a responsive cybersecurity web dashboard.

---

## ⚠️ Important Disclaimers

- **An anomaly is not an attack.** Unusual behaviour can be caused by software updates, new workloads, or misconfiguration. CyberSpy AI does not label every anomaly as malicious.
- **No system detects every attack.** CyberSpy AI does not claim complete coverage.
- **Anomaly score ≠ probability of attack.** Isolation Forest scores are relative, not calibrated probabilities.
- **Risk thresholds are configurable defaults,** not scientifically validated values until tuned on evaluation data.
- **Device fingerprints are not unique identifiers.** IP and MAC addresses can change, be hidden, or be spoofed.
- **The digital twin is an estimate,** not a perfect predictor of real-world consequences.
- **Simulated data is always labelled `SIMULATED DATA`** in the UI and reports. Synthetic data is used only for software testing, never to claim real-world detection performance.
- **Use only on networks and devices you own or are explicitly authorized to monitor.** Packet capture and network scanning without authorization may be illegal.

---

## ✨ Key Features

| Area | Description |
|---|---|
| **Real-time monitoring** | Backend APIs plus WebSocket or controlled polling feed the dashboard. No invented live traffic. |
| **Device inventory** | Registration, first/last seen, OS/type, baseline status, anomaly score, risk level. |
| **Behavioural baselines** | Per-device profiles built from observed features, not just IP addresses. |
| **ML anomaly detection** | Isolation Forest pipeline: ingest → validate → features → train → evaluate → persist → infer. |
| **Drift detection** | Tracks changes in device behaviour and explains which measurements changed. |
| **Risk scoring** | Configurable, evidence-backed scoring with categories and recommended actions. |
| **Alert management** | Statuses, filters, search, notes, approval workflow, review history. |
| **Response policy engine** | Sits between AI and firewall. The AI never runs firewall commands directly. |
| **Digital twin** | NetworkX graph simulation of firewall-rule impact with a visual topology. |
| **Windows agent** | Controlled Windows Firewall integration via PowerShell with an allowlist. |
| **Linux agent** | Controlled nftables integration in an isolated, app-owned table. |
| **Auditing & rollback** | Every action is logged. Only CyberSpy-owned rules can be rolled back. |
| **Reports** | Searchable logs and CSV export. Measured and simulated results are clearly labelled. |
| **Optional: federated learning** | Advanced module, built only after the core workflow works. |

---

## 📊 Implementation Status

Every feature is labelled honestly. This table is updated as each phase is completed **and tested**.

**Legend:** ✅ Implemented & tested · 🧪 Simulated / mock · 🛠️ In progress · 📅 Planned

| Phase | Component | Status |
|---|---|---|
| 1 | Repository structure, FastAPI backend, health endpoint | 📅 Planned |
| 1 | React + Vite dashboard shell, backend connection | 📅 Planned |
| 2 | Database models, migrations, alert management | 📅 Planned |
| 3 | ML pipeline (Isolation Forest) and evaluation | 📅 Planned |
| 4 | Device inventory and behavioural baselines | 📅 Planned |
| 5 | Monitoring-agent communication | 📅 Planned |
| 6 | Digital twin and response simulation | 📅 Planned |
| 7 | Windows Firewall agent (dry-run first) | 📅 Planned |
| 8 | Linux nftables agent (dry-run first) | 📅 Planned |
| 9 | Authorization, auditing, rollback, hardening | 📅 Planned |
| 10 | Full testing, documentation, demo preparation | 📅 Planned |
| Optional | Federated learning module | 📅 Planned |
| Optional | Autoencoder, ONNX Runtime, Wazuh integration | 📅 Planned |

---

## 🏗️ System Architecture

### High-level architecture

```mermaid
flowchart LR
    subgraph Edge["Monitored Hosts / Edge Nodes"]
        WA["Windows Agent<br/>(PowerShell, Scapy)"]
        LA["Linux Agent<br/>(nftables, logs)"]
    end

    subgraph Backend["Backend (FastAPI)"]
        API["REST + WebSocket API"]
        ING["Ingestion & Validation"]
        FE["Feature Extraction"]
        ML["Anomaly Engine<br/>(Isolation Forest)"]
        DRIFT["Drift Detector"]
        RISK["Risk Scoring"]
        POL["Response Policy Engine"]
        DT["Digital Twin<br/>(NetworkX)"]
        AUD["Audit Logger"]
    end

    DB[("PostgreSQL / SQLite")]
    UI["React Dashboard"]

    WA -->|events| API
    LA -->|events| API
    API --> ING --> FE --> ML --> RISK
    FE --> DRIFT --> RISK
    RISK --> POL --> DT
    POL -->|approved action| API
    API -->|allowlisted command| WA
    API -->|allowlisted command| LA
    API <--> DB
    AUD --> DB
    UI <-->|HTTPS / WS| API
```

### Response workflow

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Monitoring Agent
    participant API as Backend
    participant AI as Anomaly + Risk Engine
    participant Pol as Policy Engine
    participant Twin as Digital Twin
    participant Admin as Administrator
    participant FW as Firewall Agent
    participant Log as Audit Log

    Agent->>API: Network event
    API->>AI: Evaluate anomaly
    AI->>API: Anomaly score + risk score + recommendation
    API->>Pol: Check response policy
    Pol->>Twin: Simulate proposed action
    Twin-->>Pol: Impact estimate
    Pol->>Admin: Request approval (if required)
    Admin-->>Pol: Approve / Reject
    Pol->>FW: Execute approved, allowlisted action
    FW-->>Pol: Result + verification
    Pol->>Log: Record audit event
    Note over FW,Log: Success is claimed only after verification
```

### Design principles

- **Modular:** each component can be developed, tested, and maintained independently.
- **Human-in-the-loop:** real firewall changes require explicit authorization.
- **Least privilege:** the web API never gets unrestricted administrator rights.
- **Safe by default:** dry-run mode comes first. Only app-owned rules are ever modified.
- **Honest reporting:** measured vs. simulated results are always labelled.

---

## 🧰 Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React.js, Vite, JavaScript, HTML5, CSS3, Recharts, React Router, Lucide React |
| **Backend** | Python 3.11+, FastAPI, Pydantic, SQLAlchemy, Uvicorn |
| **Database** | PostgreSQL (full implementation), SQLite (development fallback), Alembic migrations |
| **Machine learning** | scikit-learn, Pandas, NumPy, Isolation Forest; optional Autoencoder and ONNX Runtime |
| **Network monitoring** | Scapy (authorized capture), Wireshark/TShark (inspection), optional Wazuh |
| **OS integration** | PowerShell and Windows Firewall interfaces; nftables on Linux |
| **Digital twin** | Python + NetworkX |
| **Testing** | Pytest, React Testing Library / Vitest, API integration tests |
| **Deployment** | Docker and Docker Compose (optional); local development without Docker |

> Dependencies are kept minimal. Exact pinned versions are recorded in `requirements.txt` and `package.json` once Phase 1 is complete and verified.

---

## 📁 Project Structure

Planned layout (created incrementally, phase by phase):

```text
cyberspy-ai/
├── README.md
├── .gitignore
├── .env.example
├── docker-compose.yml                # optional (Phase 10)
│
├── backend/
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/                      # database migrations
│   ├── app/
│   │   ├── main.py                   # FastAPI entry point
│   │   ├── core/                     # config, security, logging
│   │   ├── api/                      # routers: health, dashboard, devices, alerts, ...
│   │   ├── models/                   # SQLAlchemy models
│   │   ├── schemas/                  # Pydantic schemas
│   │   ├── services/                 # business logic
│   │   ├── ml/
│   │   │   ├── ingestion.py
│   │   │   ├── validation.py
│   │   │   ├── features.py
│   │   │   ├── training.py
│   │   │   ├── evaluation.py
│   │   │   ├── persistence.py
│   │   │   ├── inference.py
│   │   │   └── explain.py
│   │   ├── risk/                     # risk scoring engine
│   │   ├── drift/                    # behaviour drift detection
│   │   ├── policy/                   # response policy engine
│   │   ├── twin/                     # digital twin (NetworkX)
│   │   └── audit/                    # audit logging
│   ├── models_store/                 # saved ML models (git-ignored)
│   ├── data/                         # datasets (git-ignored)
│   └── tests/
│
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── api/                      # API client
│       ├── components/               # cards, charts, tables, topology
│       ├── pages/                    # Overview, Devices, Alerts, ...
│       ├── hooks/
│       ├── styles/
│       └── tests/
│
├── agents/
│   ├── windows/                      # Windows firewall agent (PowerShell + Python)
│   ├── linux/                        # Linux nftables agent
│   └── common/                       # shared validation, transport, audit helpers
│
├── federated/                        # optional advanced module
│
└── docs/
    ├── abstract.md
    ├── problem-statement.md
    ├── srs.md
    ├── architecture.md
    ├── database-schema.md
    ├── api.md
    ├── user-manual.md
    ├── testing-report.md
    ├── limitations.md
    ├── future-work.md
    └── presentation-outline.md
```

---

## ✅ Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Windows 11 | — | Initial development environment |
| Python | 3.11 or newer | Backend, ML, agents |
| Node.js | 20 LTS or newer | React/Vite frontend |
| Git | Latest | Version control |
| PostgreSQL | 15+ (optional at first) | Full database (SQLite works for early phases) |
| Npcap | Latest | Packet capture on Windows (needed for Scapy, Phase 5+) |
| Wireshark/TShark | Optional | Traffic inspection |
| Docker Desktop | Optional | Containerized deployment |
| Linux VM | Optional | Testing the Linux agent (Phase 8). WSL is **not** required |

**Check what you already have (PowerShell):**

```powershell
python --version
node --version
npm --version
git --version
```

---

## 💻 Installation (Windows 11)

All commands are for **PowerShell**. Run them from the project root unless stated otherwise.

### 1. Clone or create the project

```powershell
git clone <your-repository-url> cyberspy-ai
cd cyberspy-ai
```

### 2. Backend setup

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

> If PowerShell blocks script activation, run once (current user only):
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

### 3. Frontend setup

```powershell
cd ..\frontend
npm install
```

### 4. Environment file

```powershell
cd ..
Copy-Item .env.example .env
```

Then edit `.env` (see [Configuration](#-configuration)). **Never commit `.env`.**

### 5. Optional: PostgreSQL

Install PostgreSQL, then create a database and user:

```sql
CREATE DATABASE cyberspy;
CREATE USER cyberspy_user WITH PASSWORD 'choose-a-strong-password';
GRANT ALL PRIVILEGES ON DATABASE cyberspy TO cyberspy_user;
```

Set `DATABASE_URL` in `.env` accordingly. For early development you can keep SQLite.

---

## 🐧 Installation (Linux)

Needed only for the Linux agent (Phase 8) or if you run the backend on Linux.

```bash
# System packages (Debian/Ubuntu example)
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nftables git

# Backend / agent environment
cd cyberspy-ai/backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Check nftables is available
sudo nft --version
```

**Distribution notes:**

- Debian/Ubuntu, Fedora, and Arch package names and service management differ (`ufw`, `firewalld`, or raw nftables may already be active).
- CyberSpy AI uses its **own dedicated nftables table** so it does not interfere with existing rules.
- Run the Linux agent with a **restricted service account** and only the privileges it needs.
- Test only in a VM or lab machine you control.

---

## ⚙️ Configuration

Copy `.env.example` to `.env`. **Do not put real secrets in `.env.example`.**

```ini
# ---------- Application ----------
APP_ENV=development                 # development | production
APP_NAME=CyberSpy AI
LOG_LEVEL=INFO

# ---------- Backend ----------
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000

# ---------- Database ----------
# SQLite fallback for early development:
DATABASE_URL=sqlite:///./cyberspy.db
# PostgreSQL for the full implementation:
# DATABASE_URL=postgresql+psycopg2://cyberspy_user:CHANGE_ME@localhost:5432/cyberspy

# ---------- Security ----------
SECRET_KEY=CHANGE_ME_GENERATE_A_LONG_RANDOM_VALUE
ACCESS_TOKEN_EXPIRE_MINUTES=30
# Comma-separated list of allowed frontend origins (never "*" in production)
CORS_ORIGINS=http://localhost:5173

# ---------- Firewall agents ----------
FIREWALL_DRY_RUN=true               # keep true until you deliberately test real rules
AGENT_SHARED_TOKEN=CHANGE_ME

# ---------- ML ----------
MODEL_DIR=./models_store
RANDOM_SEED=42

# ---------- Frontend (frontend/.env) ----------
# VITE_API_BASE_URL=http://localhost:8000
```

Generate a strong secret (PowerShell):

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## ▶️ Running the Application

Open **two PowerShell windows**.

**Terminal 1: Backend**

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Terminal 2: Frontend**

```powershell
cd frontend
npm run dev
```

| Service | URL |
|---|---|
| Frontend dashboard | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| Interactive API docs (Swagger) | http://localhost:8000/docs |
| Health check | http://localhost:8000/api/health |

---

## 🧪 Verifying the Installation

1. **Backend health check**

   ```powershell
   Invoke-RestMethod http://localhost:8000/api/health
   ```

   Expected: a JSON response reporting the service status (for example `status: ok`).

2. **Swagger UI**: open http://localhost:8000/docs and confirm the endpoints are listed.

3. **Frontend**: open http://localhost:5173. The dashboard should load and show the backend connection state (connected / disconnected).

4. **Disconnected-state test**: stop the backend and refresh the dashboard. It should show a clear disconnected/error state, not fake data.

> Exact responses are confirmed and documented at the end of Phase 1. Until then, treat these as expected behaviour, not verified results.

---

## 🖥️ Dashboard Pages

**Sidebar navigation:** Overview · Live Monitoring · Devices · AI Anomaly Detection · Security Alerts · Digital Twin · Firewall Management · Security Logs · Reports · Settings

**Top cards:** Connected Devices · Events Analysed · Suspicious Events · High-Risk Alerts · Pending Actions · Successful Firewall Actions

**Overview page includes:** device statistics, incoming/outgoing traffic chart, anomaly count over time, alert distribution, risk-level distribution, recent events, recent firewall actions, system health, agent status.

**UI rules:**

- Dark navy/charcoal theme with blue/cyan accents. Green = normal, amber = warning, red = critical.
- Loading, empty, error, and disconnected states for every data view.
- Any demonstration data is clearly tagged **SIMULATED DATA**.
- Accessible text contrast and keyboard-friendly controls.

---

## 🤖 AI Anomaly Detection Pipeline

**Initial model:** Isolation Forest (scikit-learn). Autoencoder and ONNX Runtime are optional later additions.

### Pipeline stages

```mermaid
flowchart LR
    A[Load dataset / events] --> B[Validate & clean]
    B --> C[Handle missing values]
    C --> D[Select features]
    D --> E[Train / test split<br/>no leakage]
    E --> F[Train model]
    F --> G[Evaluate]
    G --> H[Save model + version]
    H --> I[Load for inference]
    I --> J[Anomaly score]
    J --> K[Record prediction]
```

### Candidate features

Flow duration · packet count · byte count · average packet size · connection frequency · incoming/outgoing ratio · failed connection attempts · protocol information.

> Only features **actually available** from the chosen dataset or monitoring source are used.

### Evaluation

When labelled data is available the detector is evaluated with:

- Precision
- Recall
- F1-score
- False-positive rate

Rules followed:

- Fit scalers and models on **training data only** to avoid data leakage.
- Fix random seeds for reproducibility.
- Never train on random fabricated data and claim real-attack detection.
- Synthetic data is allowed for software testing only and must be labelled.
- Reported metrics are always **measured** values from a stated dataset. Nothing is invented.

### Datasets

A public, properly licensed network-intrusion dataset will be chosen in Phase 3 (the choice and its limitations will be documented). Place downloaded files in `backend/data/` (git-ignored). Dataset citations will be added only for datasets actually used.

---

## 🎯 Risk Scoring

The anomaly score and the risk score are **different things**:

| Concept | Meaning |
|---|---|
| **Anomaly score** | How unusual an observation is compared with what the model learned. |
| **Risk score** | A configurable combination of anomaly score and context. |

**Possible inputs:** anomaly score, traffic-volume deviation, connection-frequency deviation, destination reputation (only if a reliable source exists), device criticality, repeated suspicious events, existing alerts.

**Outputs:** risk score, risk category, supporting evidence, recommended action, uncertainty information where meaningful.

**Classification levels:**

1. Normal activity
2. Anomalous activity
3. Suspected threat
4. Confirmed threat (only with sufficient evidence)

Thresholds and weights are stored in configuration and can be tuned using evaluation data.

---

## 📈 Device Behaviour Drift Detection

For each device the system:

- Maintains a baseline of selected traffic features.
- Compares current behaviour with history.
- Detects significant changes.
- Records when the baseline was last updated.
- Explains **which measurements** changed.
- **Does not blindly update** baselines with suspicious data.
- Supports legitimate changes (software updates, reconfiguration, new workloads) via administrator review.

A dashboard view shows behavioural changes over time. A change is **not automatically malicious**.

---

## 🧭 Response Policy Engine

The policy engine sits **between the AI and the firewall**. The AI never executes firewall commands.

**Workflow:**

1. Observe an event
2. Evaluate the anomaly
3. Calculate the risk score
4. Generate a recommendation
5. Check the response policy
6. Simulate the proposed action (digital twin)
7. Request approval if required
8. Execute the approved action through the agent
9. Verify the result
10. Record the audit event
11. Provide rollback when appropriate

**Possible actions:** continue monitoring · generate alert · increase monitoring · request investigation · recommend blocking a specific connection · apply an approved test firewall rule · request isolation of a test device.

**Safeguards:**

- Not every anomaly is blocked.
- Broad rules are never applied from an unverified AI prediction alone.
- Anti-lockout protection (for example, never blocking the administrator's own session, the backend, or agent communication paths).

---

## 🕸️ Digital Twin

A lightweight simulation of the network built with **Python + NetworkX**.

**Graph contents:** devices, connections, important services, communication paths, device criticality, proposed firewall rules.

**Given a proposed response, the twin estimates:**

- Which communication paths are affected
- Whether important services could lose connectivity
- Whether a narrower alternative rule exists
- Which devices may be disrupted
- Whether administrator review is needed

**Dashboard:** a visual topology with clear visual distinction between:

| State | Meaning |
|---|---|
| Simulated | Result from the digital twin |
| Observed | Real state reported by agents |
| Proposed | Suggested but not approved |
| Approved | Authorized by an administrator |
| Verified executed | Applied **and** confirmed by verification |

**Limitation:** predictions are validated only against controlled test scenarios. The twin does not perfectly predict real-world behaviour.

---

## 🔥 Firewall Integration and Safety Model

### Shared safety rules (both OSes)

- ✅ Allowlist of supported actions only
- ✅ Strict validation of IP addresses and rule parameters
- ✅ Least-privilege execution
- ✅ Explicit authorization for real changes
- ✅ **Dry-run mode is the default** (`FIREWALL_DRY_RUN=true`)
- ✅ Every app-created rule carries a unique ID / ownership marker
- ✅ Rollback only for rules owned by CyberSpy AI
- ✅ Success claimed **only after verification**
- ✅ Every action written to the audit log
- ❌ No arbitrary shell commands from web requests
- ❌ No unrestricted administrator access exposed to the frontend or API
- ❌ No disabling the firewall, no deleting pre-existing rules

### Windows agent (Phase 7)

| Capability | Notes |
|---|---|
| Check firewall status | Read-only |
| Read relevant rules | Read-only |
| Create approved test rules | Named with a CyberSpy ownership prefix |
| Verify rule exists | Required before reporting success |
| Remove app-owned rules | Only rules matching the ownership marker |
| Audit log | Every request and result |

Run the agent from an elevated PowerShell **only when intentionally testing real rules**, and only on a machine you are comfortable experimenting on.

### Linux agent (Phase 8)

| Capability | Notes |
|---|---|
| Check firewall status | Read-only |
| Inspect app test rules | Within the dedicated table |
| Create approved rules | In a dedicated nftables table (for example `inet cyberspy`) |
| Verify applied config | Required before reporting success |
| Remove app-owned rules | Only inside the app-managed table |

Rules: never flush the existing ruleset, never overwrite system policies, never change a remote server without explicit authorization. Test configurations are kept separate from production configurations.

---

## 🗄️ Database Design

Managed with **SQLAlchemy** and **Alembic** migrations. PostgreSQL for the full build; SQLite for early development.

| Table | Purpose |
|---|---|
| `users` | Dashboard accounts, roles, password hashes |
| `devices` | Device inventory |
| `device_profiles` | Behavioural baselines per device |
| `monitoring_agents` | Registered agents and their status |
| `network_events` | Observed network events/flows |
| `anomaly_predictions` | Model outputs per event |
| `alerts` | Security alerts and review history |
| `response_policies` | Configurable policy rules |
| `response_simulations` | Digital twin simulation results |
| `firewall_actions` | Proposed/approved/executed/verified actions |
| `audit_logs` | Immutable-style audit trail |
| `model_versions` | Trained model metadata and metrics |
| `system_settings` | Configurable thresholds and options |

Design rules: primary and foreign keys, timestamps, indexes on lookup columns, validated input, ORM-parameterized queries, no plaintext passwords, secrets only in environment variables.

The full schema and an ER diagram will be added to `docs/database-schema.md` in Phase 2.

---

## 🔐 Authentication and Authorization

| Role | Permissions |
|---|---|
| **Administrator** | Full dashboard access, approve/reject actions, manage settings and agents |
| **Analyst (read-only)** | View dashboards, alerts, logs, reports. Cannot change firewall state |

Features: login/logout, secure password hashing (e.g., bcrypt/argon2), token or session handling, role checks on sensitive routes, request validation, rate limiting on sensitive endpoints.

Rules: no hard-coded secrets, no wildcard CORS in production, no unauthenticated firewall endpoints.

---

## 🔌 API Overview

> Planned endpoints. The final reference is generated by FastAPI at `/docs` and written to `docs/api.md`.

| Method | Endpoint | Description | Phase |
|---|---|---|---|
| GET | `/api/health` | Service health check | 1 |
| GET | `/api/dashboard/summary` | Overview card/chart data | 1–2 |
| POST | `/api/auth/login` | Authenticate user | 9 |
| POST | `/api/auth/logout` | End session | 9 |
| GET/POST | `/api/devices` | List / register devices | 4 |
| GET | `/api/devices/{id}` | Device detail and baseline | 4 |
| GET | `/api/alerts` | List, filter, search alerts | 2 |
| GET | `/api/alerts/{id}` | Alert detail and evidence | 2 |
| PATCH | `/api/alerts/{id}/status` | Update alert status | 2 |
| POST | `/api/alerts/{id}/notes` | Add investigation note | 2 |
| POST | `/api/alerts/{id}/approve` | Approve recommended action | 9 |
| POST | `/api/alerts/{id}/reject` | Reject recommended action | 9 |
| POST | `/api/ml/train` | Train model | 3 |
| GET | `/api/ml/models` | List model versions and metrics | 3 |
| POST | `/api/ml/predict` | Score observations | 3 |
| POST | `/api/agents/events` | Agent submits events | 5 |
| POST | `/api/twin/simulate` | Simulate a proposed rule | 6 |
| GET | `/api/firewall/actions` | Action history | 7–8 |
| POST | `/api/firewall/actions/{id}/execute` | Execute an **approved** action | 7–9 |
| POST | `/api/firewall/actions/{id}/rollback` | Roll back an app-owned rule | 9 |
| GET | `/api/logs` | Searchable security logs | 9 |
| GET | `/api/reports/export.csv` | CSV export | 10 |

---

## 🧪 Testing

Run from the relevant folder after activating the virtual environment.

```powershell
# Backend + AI + twin + firewall (mocked)
cd backend
pytest -v

# Frontend
cd ..\frontend
npm test
```

| Area | Planned tests |
|---|---|
| **Backend** | Health, dashboard, input validation, authentication, alert creation, risk scoring, DB persistence, policy decisions |
| **AI** | Training, loading, missing-value handling, prediction output, reproducibility, evaluation metrics |
| **Digital twin** | Network creation, rule simulation, connectivity impact, unknown device handling, simulation logging |
| **Firewall** | Dry-run, invalid input rejection, permission failures, rule verification, rollback of owned rules |
| **Frontend** | Dashboard rendering, loading/error states, alert display, approval workflow |

> **Firewall tests use mocks.** The standard test suite never runs real, destructive firewall commands.

Test results are recorded in `docs/testing-report.md` only after they are actually run.

---

## 🛡️ Security Considerations

- Treat the backend as an internet-facing service even in a lab. Always require authentication.
- Never commit `.env`, model files containing sensitive data, or captured packets.
- Packet captures can contain personal or confidential data. Capture only with authorization and store securely.
- Agents authenticate to the backend with tokens and communicate over TLS outside localhost.
- The firewall agent exposes **only** allowlisted operations with validated parameters.
- Federated learning (if implemented) has privacy limits: model updates can leak information about local data and can be poisoned. Mitigations and residual risks will be documented.
- Keep dependencies updated and review them for known vulnerabilities.

---

## 🗺️ Development Phases

| Phase | Goal | Done when |
|---|---|---|
| **1** | Repo structure, FastAPI backend, React dashboard, health endpoint | Both servers run and the dashboard shows backend status |
| **2** | Database integration and alert management | Alerts persist and can be filtered, updated, and annotated |
| **3** | ML pipeline and evaluation | Model trains, saves, loads, scores, and reports measured metrics |
| **4** | Device inventory and baselines | Devices have profiles and drift views |
| **5** | Monitoring-agent communication | Agent sends real events to the backend |
| **6** | Digital twin and simulation | Rule impact is simulated and visualized |
| **7** | Windows Firewall integration | Dry-run and approved test rules work, verified and rolled back |
| **8** | Linux nftables integration | Same, inside an app-owned table |
| **9** | AuthN/AuthZ, auditing, rollback, hardening | Roles enforced, audit trail complete |
| **10** | Final testing, documentation, demo | Full test report and presentation ready |

Each phase must run and be tested before the next begins.

---

## ⛔ Known Limitations

- Anomaly detection yields false positives and false negatives. It is not a complete security solution.
- Isolation Forest scores are not calibrated probabilities.
- Model performance depends on the training data and may not generalize to other networks.
- Real-time performance depends on hardware and capture volume. Edge benchmarks will be measured, not assumed.
- Windows packet capture requires Npcap and administrator privileges. Some traffic (for example, encrypted payloads) is not inspectable.
- Device identity cannot be guaranteed due to IP/MAC changes and spoofing.
- The digital twin is a model and may miss real-world complexity (NAT, routing, application behaviour).
- Linux behaviour varies across distributions and existing firewall managers.
- Federated learning, Autoencoder, ONNX, and Wazuh integrations are optional and may not be included.

---

## 🔭 Future Enhancements

- Autoencoder and ensemble detection models
- ONNX Runtime export for faster edge inference
- Federated learning across multiple edge nodes
- Wazuh endpoint-monitoring integration
- Threat-intelligence feeds for destination reputation (with reliable sources)
- Additional firewall back-ends (for example, `firewalld`, `iptables`)
- Multi-tenant support and SSO
- Automated threshold tuning from labelled feedback
- Kubernetes deployment

---

## 🩺 Troubleshooting

| Problem | Likely cause / fix |
|---|---|
| `Activate.ps1 cannot be loaded` | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| `python` not recognized | Reinstall Python and tick **Add Python to PATH** |
| Port 8000 or 5173 already in use | Stop the other process or change the port in `.env` / Vite config |
| Frontend shows "disconnected" | Backend not running, wrong `VITE_API_BASE_URL`, or CORS origin missing |
| CORS error in browser console | Add the frontend origin to `CORS_ORIGINS` |
| Scapy cannot capture packets | Install Npcap and run with the required privileges (Phase 5+) |
| `npm install` fails | Check Node version (`node --version`) and clear cache with `npm cache clean --force` |
| Database connection error | Verify `DATABASE_URL`, and that PostgreSQL is running (or use SQLite) |

---

## 🤝 Contributing and Conventions

- One milestone at a time. Keep the app runnable after each one.
- Complete files, clear error handling, and application logs.
- Configuration through environment variables only.
- Placeholders must be clearly marked. Never present static data as live monitoring results.
- Do not claim code works until it has been tested.
- Do not invent research citations or experimental results.
- Suggested commit style: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`.

---

## 📚 Documentation Index

The following documents will be produced in `docs/` as the project progresses:

1. Project abstract
2. Problem statement
3. Project objectives
4. Literature review outline
5. System requirements
6. Software Requirements Specification (SRS)
7. Architecture description (with Mermaid diagrams)
8. Database schema
9. API documentation
10. Installation guide
11. User manual
12. Testing report
13. Known limitations
14. Future enhancements
15. Major-project presentation outline

Each document identifies features as **implemented**, **simulated**, or **planned**.

---

## 📄 License and Acknowledgements

- **License:** to be chosen by the project author (for example MIT for open source, or "All rights reserved" for academic submission). Add a `LICENSE` file accordingly.
- **Acknowledgements:** open-source projects used (FastAPI, React, scikit-learn, Scapy, NetworkX, Recharts, and others), your project guide/supervisor, and your institution. Dataset and paper citations will be added **only** for sources actually used.

---

*CyberSpy AI is an educational major project. Use responsibly and only on systems you are authorized to monitor.*
