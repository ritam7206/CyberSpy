# CyberSpy AI

**A Lightweight Edge-AI Framework for Real-Time Anomaly Detection and Prevention in Heterogeneous IoT and Computer Networks**

---

## Table of Contents

1. [Role](#1-role)
2. [Project Objective](#2-project-objective)
3. [Application Type](#3-application-type)
4. [Technology Stack](#4-technology-stack)
5. [User Interface and Design](#5-user-interface-and-design)
6. [Overview Dashboard](#6-overview-dashboard)
7. [Device Management](#7-device-management)
8. [AI Anomaly Detection Engine](#8-ai-anomaly-detection-engine)
9. [Device Behaviour Drift Detection](#9-device-behaviour-drift-detection)
10. [Risk Scoring Engine](#10-risk-scoring-engine)
11. [Security Alert Management](#11-security-alert-management)
12. [Windows Firewall Integration](#12-windows-firewall-integration)
13. [Linux Firewall Integration](#13-linux-firewall-integration)
14. [Response Policy Engine](#14-response-policy-engine)
15. [Digital Twin (Signature Feature)](#15-digital-twin-signature-feature)
16. [Optional Federated Learning](#16-optional-federated-learning)
17. [Database Design](#17-database-design)
18. [Authentication and Authorization](#18-authentication-and-authorization)
19. [Security Logs and Reports](#19-security-logs-and-reports)
20. [Testing Requirements](#20-testing-requirements)
21. [Project Documentation](#21-project-documentation)
22. [Development Rules](#22-development-rules)
23. [Required Development Phases](#23-required-development-phases)
24. [Start Now](#24-start-now)

---

## 1. Role

Act as a senior full-stack developer, AI/ML engineer, cybersecurity engineer, network security researcher, UI/UX designer, and software architect.

The task is to help build a complete, functional, well-documented **final-year Computer Engineering major project** called **CyberSpy AI**.

**Do not** build only a static frontend or a demo dashboard.

Build a working application with:

- A real backend
- A database
- A machine-learning detection engine
- Security monitoring
- A digital twin simulator
- Controlled Windows/Linux firewall integration

**Working style:**

- I am a student and need step-by-step instructions.
- Explain complicated concepts in simple language.
- Generate actual working source code, not pseudocode.
- Do not skip important files or leave core functionality as TODO comments.
- If a feature cannot be implemented in the current environment, explain the limitation and provide a working alternative.
- Build the project incrementally and verify each stage before proceeding.

---

## 2. Project Objective

Create an AI-powered cybersecurity platform that monitors network behaviour, detects anomalies, identifies suspicious devices, calculates risk scores, and recommends appropriate security responses.

**Goals:**

1. Detect unusual network traffic in near real time.
2. Learn behavioural baselines for different devices.
3. Identify suspicious changes in device behaviour.
4. Display understandable security alerts.
5. Calculate a risk score for suspicious events.
6. Simulate proposed security actions using a digital twin.
7. Integrate with Windows Firewall and Linux firewalls.
8. Require authorization before performing sensitive actions.
9. Verify firewall actions and maintain an audit trail.
10. Minimize unnecessary disruption to legitimate traffic.
11. Support lightweight execution on edge computers.
12. Provide a responsive cybersecurity web dashboard.

> ⚠️ Do not claim that all anomalies are attacks or that the system can detect every cyberattack.

---

## 3. Application Type

Build a **responsive web application** with background security agents for Windows and Linux.

- The web application must run in a browser.
- The initial development environment is **Windows 11**.
- The system should support Linux through a separate Linux agent or virtual machine.
- Do not require WSL for the initial development process.
- Use a modular architecture so each component can be developed, tested, and maintained independently.

---

## 4. Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React.js, Vite, JavaScript, HTML5, CSS3, Recharts (charts), React Router (navigation), Lucide React (icons) |
| **Backend** | Python, FastAPI, Pydantic, SQLAlchemy, Uvicorn |
| **Database** | PostgreSQL (full implementation); SQLite (optional development fallback) |
| **Machine Learning** | Scikit-learn, Pandas, NumPy, Isolation Forest (initial detector), Autoencoder (optional advanced), ONNX Runtime (optional edge optimization) |
| **Network Monitoring** | Scapy (authorized packet capture/analysis), Wireshark/TShark (traffic inspection), Wazuh (optional endpoint monitoring) |
| **OS Integration** | PowerShell + supported Windows Firewall interfaces; nftables for Linux; Linux security logs where permitted |
| **Testing** | Pytest, React testing tools, API integration tests |
| **Deployment** | Docker and Docker Compose where appropriate; local development without Docker |

**Notes:**

- Do not add unnecessary dependencies.
- Check package compatibility and explain installation commands for Windows PowerShell.

---

## 5. User Interface and Design

Design a professional cybersecurity dashboard suitable for a college major-project demonstration.

### Visual Style

- Dark cybersecurity theme
- Professional enterprise interface
- Dark navy and charcoal backgrounds
- Subtle blue and cyan accents
- **Green** = normal, **Amber** = warning, **Red** = critical
- Clean typography
- Responsive cards
- Modern charts
- Clear navigation
- Accessible text and controls

Avoid excessive animations, clutter, and decorative elements that reduce usability.

### Sidebar Navigation

1. Overview
2. Live Monitoring
3. Devices
4. AI Anomaly Detection
5. Security Alerts
6. Digital Twin
7. Firewall Management
8. Security Logs
9. Reports
10. Settings

### Top Dashboard Cards

- Connected Devices
- Events Analysed
- Suspicious Events
- High-Risk Alerts
- Pending Actions
- Successful Firewall Actions

> ⚠️ Do not display fake values as actual monitoring results. If demonstration data is used, clearly label it **SIMULATED DATA**.

---

## 6. Overview Dashboard

The overview page contains:

- Connected device statistics
- Network traffic chart
- Incoming and outgoing traffic
- Anomaly count over time
- Security alert distribution
- Risk-level distribution
- Recent security events
- Recent firewall actions
- System health
- Monitoring-agent status

**Requirements:**

- The dashboard must obtain its data from backend APIs.
- Use WebSockets or controlled polling for updates.
- Display loading, empty, error, and disconnected states.
- Do not invent live network activity.

---

## 7. Device Management

Create a device management module.

### Device Fields

| Field | Notes |
|---|---|
| Device ID | |
| Device name | |
| IP address | if available |
| MAC address | if visible |
| Operating system | if known |
| Device type | if known |
| First-seen timestamp | |
| Last-seen timestamp | |
| Device status | |
| Behavioural baseline status | |
| Recent anomaly score | |
| Risk level | |

### Requirements

- Implement device registration and device inventory.
- Create behavioural profiles based on **observed features**, not merely the IP address.
- Support device-specific normal behaviour.
- Account for the fact that IP and MAC addresses can change, be hidden, or be spoofed.
- Do not claim that fingerprinting uniquely identifies every physical device.
- Do not scan networks without authorization.

---

## 8. AI Anomaly Detection Engine

Implement a **genuine** machine-learning pipeline, starting with **Isolation Forest**.

### Separate Modules

- Data ingestion
- Data validation
- Feature extraction
- Model training
- Model evaluation
- Model persistence
- Inference
- Risk scoring
- Explanation generation

### Candidate Network Features

- Flow duration
- Packet count
- Byte count
- Average packet size
- Connection frequency
- Incoming/outgoing traffic ratio
- Failed connection attempts (when available)
- Protocol information (when available)

Use **only** features actually available in the selected dataset or monitoring source.

### Pipeline Must Support

1. Loading a dataset
2. Cleaning invalid data
3. Handling missing values
4. Selecting features
5. Training the model
6. Saving the trained model
7. Loading the model for inference
8. Detecting anomalous observations
9. Producing anomaly scores
10. Recording predictions
11. Evaluating model performance

### Rules

- Do not assume an Isolation Forest score is a calibrated probability of an attack.
- Clearly distinguish **anomaly scores** from **risk scores**.
- If labelled data is available, evaluate using **precision, recall, F1-score, and false-positive rate**.
- Avoid data leakage between training and test sets.
- Do not train on random fabricated data and then claim it detects real attacks.
- Synthetic data may be used for initial software testing, but label those results appropriately.

---

## 9. Device Behaviour Drift Detection

Implement a module that tracks changes in a device's behavioural baseline over time.

**For each device:**

- Maintain a baseline of selected traffic features.
- Compare current observations with historical behaviour.
- Detect significant changes.
- Record when the baseline was updated.
- Explain which measurements changed.
- Avoid updating the baseline blindly with suspicious data.

**Also:**

- Support legitimate changes (software updates, reconfiguration, changing workloads).
- Provide a dashboard view showing behavioural changes.
- Do not automatically label every change as malicious.

---

## 10. Risk Scoring Engine

Implement a **configurable** risk-scoring engine.

### Possible Inputs

- Anomaly score
- Traffic volume deviation
- Connection frequency deviation
- Destination reputation (only when a reliable source exists)
- Device criticality
- Repeated suspicious events
- Existing security alerts

### Outputs

- Risk score
- Risk category
- Supporting evidence
- Recommended action
- Confidence or uncertainty information (where meaningful)

### Rules

- Use configurable thresholds.
- Do not treat arbitrary thresholds as scientifically validated values.
- Allow thresholds to be tuned using evaluation data.
- Clearly separate:
  - Normal activity
  - Anomalous activity
  - Suspected threats
  - Confirmed threats (only with sufficient evidence)

---

## 11. Security Alert Management

### Alert Fields

- Alert ID
- Timestamp
- Device ID
- Event type
- Anomaly score
- Risk score
- Risk category
- Supporting evidence
- Recommended action
- Current status
- Review history

### Supported Statuses

`New` → `Investigating` → `Awaiting Approval` → `Approved` / `Rejected` → `Resolved`

### Authorized Users Can

- View alerts
- Filter alerts
- Search alerts
- Inspect evidence
- Approve or reject recommended actions
- Add investigation notes
- Review previous actions

Store alert history in the database.

---

## 12. Windows Firewall Integration

Implement a **separate Windows security agent** using supported Windows Firewall management interfaces and PowerShell where appropriate.

### Required Capabilities

- Check firewall status where supported
- Read relevant firewall rules
- Create explicitly approved test rules
- Verify whether a rule exists
- Record the result of an action
- Remove application-owned test rules
- Maintain an audit log

### Safety Rules

- ❌ Do not disable Windows Firewall.
- ❌ Do not delete existing firewall rules.
- ❌ Do not execute arbitrary shell commands supplied by a web request.
- ❌ Do not expose unrestricted administrator privileges to the frontend or API.
- ✅ Use an allowlist of supported actions.
- ✅ Use strict validation for IP addresses and rule parameters.
- ✅ Use least-privilege permissions wherever possible.
- ✅ Require explicit authorization for real firewall changes.
- ✅ Prefer a **dry-run mode** during initial development.
- ✅ Give every application-created rule a unique identifier or ownership marker.
- ✅ Provide safe rollback for rules owned by CyberSpy AI.
- ✅ Do not claim an action succeeded until it has been **verified**.

---

## 13. Linux Firewall Integration

Implement a **separate Linux security agent** using **nftables**.

### Required Capabilities

- Check relevant firewall status
- Inspect the application's test rules
- Create approved rules in a dedicated application-managed table (or other clearly isolated configuration)
- Verify the applied configuration
- Record action results
- Remove only rules owned by CyberSpy AI

### Safety Rules

- ❌ Do not flush the existing firewall ruleset.
- ❌ Do not overwrite existing system firewall policies.
- ❌ Do not make changes to a remote server without explicit authorization.
- ✅ Use restricted privileges and validated inputs.
- ✅ Provide a simulation / dry-run mode.
- ✅ Document differences between Linux distributions.
- ✅ Clearly separate test configurations from production configurations.

---

## 14. Response Policy Engine

Build a policy engine **between** the AI and the firewall. The AI must not directly execute firewall commands.

### Workflow

1. Observe an event
2. Evaluate the anomaly
3. Calculate the risk score
4. Generate a recommendation
5. Check the response policy
6. Simulate the proposed action
7. Request approval if required
8. Execute the approved action through the agent
9. Verify the result
10. Record the audit event
11. Provide rollback when appropriate

### Possible Actions

- Continue monitoring
- Generate an alert
- Increase monitoring
- Request investigation
- Recommend blocking a specific connection
- Apply an approved test firewall rule
- Request isolation of a test device

### Rules

- Do not automatically block every anomaly.
- Do not apply broad firewall rules based only on an unverified AI prediction.
- Include safeguards against accidental lockout.

---

## 15. Digital Twin (Signature Feature)

Implement a lightweight cybersecurity digital twin using **Python and NetworkX**.

### Network Graph Contents

- Devices
- Network connections
- Important services
- Communication paths
- Device criticality
- Proposed firewall rules

### Capabilities

An administrator selects a proposed response, and the twin simulates the expected consequences.

**Estimate:**

- Which communication paths would be affected
- Whether important services could lose connectivity
- Whether alternative, narrower rules are possible
- Which devices may be disrupted
- Whether administrator review is needed

Display the result on the React dashboard with a **visual network topology**.

### Clearly Distinguish

- Simulated state
- Observed real state
- Proposed actions
- Approved actions
- Verified executed actions

> ⚠️ Do not claim the digital twin perfectly predicts all real-world consequences. Validate its predictions against controlled test scenarios.

---

## 16. Optional Federated Learning

Design federated learning as an **optional advanced module** — not a dependency for the initial prototype.

Multiple edge nodes may train local models and exchange model updates.

**Include:**

- A coordinator
- Local training
- Model-update aggregation
- Version management
- Update validation
- Model distribution
- Basic monitoring

**Also:**

- Explain the privacy limitations and security risks of exchanging model updates.
- Implement only after the basic detection, dashboard, and firewall workflows are working.

---

## 17. Database Design

Create appropriate database models and migrations.

### Suggested Entities

- `users`
- `devices`
- `device_profiles`
- `monitoring_agents`
- `network_events`
- `anomaly_predictions`
- `alerts`
- `response_policies`
- `response_simulations`
- `firewall_actions`
- `audit_logs`
- `model_versions`
- `system_settings`

### Requirements

- Use primary keys, foreign keys, timestamps, indexes, and suitable data types.
- Use database migrations.
- Validate data before insertion.
- Use parameterized queries through the ORM.
- Do not store passwords in plaintext.
- Store secrets in environment variables.

---

## 18. Authentication and Authorization

Implement authentication suitable for an administrator dashboard.

**Include:**

- Login and logout
- Secure password hashing
- Role-based authorization
- Administrator role
- Read-only analyst role
- Authorization checks for sensitive operations
- Secure session or token handling
- Input validation
- Rate limiting for sensitive endpoints

**Rules:**

- Do not place passwords, API keys, or secrets in source code.
- Do not enable unrestricted CORS in production.
- Do not expose firewall management endpoints to unauthenticated users.
- Protect the application from common web vulnerabilities.

---

## 19. Security Logs and Reports

### Searchable Security Logs Record

- Event timestamp
- Source component
- Device identifier
- Event category
- Risk score
- Recommended response
- Approval status
- Execution result
- Error details (where appropriate)

### Reports

- Total events analysed
- Anomalies detected
- Alerts by severity
- False-positive evaluation results
- Detection latency
- Firewall action history
- Model performance metrics

**Rules:**

- Allow authorized users to export reports as **CSV**.
- Never fabricate performance statistics.
- Clearly label simulated and measured results.

---

## 20. Testing Requirements

Write automated tests.

| Area | Tests |
|---|---|
| **Backend** | Health endpoint, dashboard endpoint, input validation, authentication, alert creation, risk scoring, database persistence, response policy decisions |
| **AI** | Model training, model loading, missing-value handling, prediction output, reproducibility, evaluation metrics |
| **Digital Twin** | Network creation, proposed rule simulation, connectivity impact, unknown device handling, simulation result logging |
| **Firewall** | Dry-run mode, invalid input rejection, permission failure handling, rule verification, rollback of application-owned rules |
| **Frontend** | Dashboard rendering, API loading states, error states, alert display, approval workflow |

- Use **mocks** for firewall tests.
- Never require real destructive firewall operations in the standard automated test suite.

---

## 21. Project Documentation

Generate:

1. README.md
2. Project abstract
3. Problem statement
4. Project objectives
5. Literature review outline
6. System requirements
7. Software requirements specification
8. Architecture description
9. Database schema
10. API documentation
11. Installation guide
12. User manual
13. Testing report
14. Known limitations
15. Future enhancements
16. Major-project presentation outline

**Rules:**

- Provide architecture diagrams using Mermaid where useful.
- Clearly identify **implemented**, **simulated**, and **planned** features.
- Do not invent research citations or experimental results.

---

## 22. Development Rules

1. First inspect the available project files.
2. Explain the proposed architecture.
3. Create a development plan.
4. Implement one milestone at a time.
5. Generate complete files, not isolated snippets only.
6. Explain exactly where every file belongs.
7. Provide Windows PowerShell commands.
8. Provide Linux commands when required.
9. Test each milestone before proceeding.
10. Fix errors before adding more features.
11. Keep frontend and backend configurations consistent.
12. Use environment variables for configuration.
13. Keep development secrets out of version control.
14. Provide `.env.example` without real secrets.
15. Create `requirements.txt` or an appropriate dependency manifest.
16. Create a useful `.gitignore`.
17. Use clear error handling and application logs.
18. Avoid unnecessary complexity.
19. Do not replace real functionality with static data without clearly identifying it as a placeholder.
20. Do not claim untested code works.
21. Explain all important assumptions.
22. Keep the application runnable after each milestone.

When a required environment, credential, device, or permission is unavailable, implement a **safe mock or simulation** and document the limitation.

---

## 23. Required Development Phases

| Phase | Scope |
|---|---|
| **1** | Repository structure, FastAPI backend, React frontend, initial dashboard |
| **2** | Database integration and alert management |
| **3** | AI anomaly-detection pipeline and evaluation |
| **4** | Device inventory and behavioural baselines |
| **5** | Monitoring-agent communication |
| **6** | Digital twin and response simulation |
| **7** | Controlled Windows Firewall integration |
| **8** | Controlled Linux nftables integration |
| **9** | Authorization, auditing, rollback, and security hardening |
| **10** | Testing, documentation, and final demonstration prep |

Do not generate the entire system in one unverified code dump. Complete each phase so it can be run and tested.

---

## 24. Start Now

Begin with **PHASE 1**.

1. Explain the architecture in simple language.
2. Show the exact project folder structure.
3. List the prerequisites.
4. Provide installation commands for Windows 11.
5. Create the FastAPI backend.
6. Create the React dashboard.
7. Connect the dashboard to the backend.
8. Add a health-check endpoint.
9. Add clear instructions for starting both servers.
10. Verify the expected results and explain how I can test them.

After Phase 1 works, **wait for me to confirm** before proceeding to Phase 2.

> I want a real, maintainable major project, not just a beautiful dashboard with fake cybersecurity data.
