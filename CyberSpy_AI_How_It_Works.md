# CyberSpy AI: Complete Guide (How It Works)

Windows-native, AI-assisted security monitoring and response system.
Pipeline: **Collect → Store → Detect → Decide → Act → Report**

---

## 1. What is CyberSpy AI?

CyberSpy AI is an installable Windows desktop application with a background agent service. It:

1. Watches a Windows machine continuously (logins, processes, files, network, registry, USB, etc.).
2. Stores everything in an encrypted, tamper-evident local database.
3. Analyzes events with **rules** (known attack patterns) and **machine learning** (unusual behavior).
4. Produces alerts with a risk score **and a plain-English explanation of why**.
5. Responds depending on confidence: act automatically, ask the admin for one-click approval, or just notify.
6. Shows everything in a dashboard and sends daily reports.

**Why it exists:** most security tools are built for Linux server stacks (ELK, Wazuh, Elasticsearch) and drown users in raw alerts. CyberSpy AI is a single, easy-to-install app for Windows desktops and laptops that cuts the noise and explains itself.

**What it is not:** a replacement for Windows Defender, updates, backups, MFA, or good habits. It is an *additional layer* that adds visibility, early warning, a tamper-evident record, and some automated response.

---

## 2. Big Picture

```
 Windows Event Log / Sysmon / ETW / File watchers / Registry / USB / Network
                              │
                              ▼
                    ┌───────────────────┐
                    │  AGENT (service)  │  collects + normalizes events
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │  STORAGE          │  encrypted SQLite, hash-chained
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │  DETECTION ENGINE │  rules + ML + baselines
                    └─────────┬─────────┘
                              ▼  alert + risk score + explanation
                    ┌───────────────────┐
                    │  RESPONSE ENGINE  │  decides Tier 1 / 2 / 3
                    └───┬─────┬─────┬───┘
                        │     │     │
                  Tier 1│  Tier 2   │Tier 3
                  auto  │  confirm  │ notify only
                        ▼     ▼     ▼
                 Firewall   Dashboard   Email/Slack
                 Quarantine  prompt
                              │
                              ▼
                    ┌───────────────────┐
                    │ DASHBOARD + REPORTS│
                    └───────────────────┘
```

A **watchdog** process monitors the agent. If the agent stops, the watchdog restarts it and flags the downtime as suspicious.

---

## 3. The Components in Detail

### 3.1 Agent (Windows Service)
- Runs in the background as a dedicated **low-privilege** service account.
- Subscribes to Windows Event Log channels (Security, System, Application) and, if Sysmon is installed, its channel for process, network, and driver events.
- Also runs watchers: file integrity, registry/persistence, USB, new accounts, firewall/Defender status, etc.
- **Normalizes** every event into one common format:
  `timestamp, source, event_type, user, device, raw_payload`
- Buffers events in memory and writes them to storage in batches (less disk I/O).
- On startup it performs a **self-integrity check** (hashes its own binary and compares it with a signed manifest).
- Exposes a **heartbeat** the watchdog checks every few seconds.

**Example:** a failed login happens → Windows writes Event ID **4625** → the agent picks it up within seconds → normalizes it → queues it for the database and detection engine.

### 3.2 Storage
- **SQLite + SQLCipher**: a local database encrypted at rest.
- **Hash-chained logs**: every event row stores `prev_hash` and its own `hash`.
  - `hash = SHA256(prev_hash + timestamp + device + source + event_type + user + payload)`
  - If an attacker edits or deletes an old row, every later hash stops matching, so the tampering is detectable.
  - This is *not* a blockchain (no network, no consensus): just a lightweight local technique with the same tamper-evidence benefit.
- A scheduled job periodically **verifies the chain**. The latest chain head is also sealed in a separate protected spot so wholesale truncation is detectable.
- Log rotation, retention policy, compression, backup and restore are supported.

**Why it matters:** an attacker's first move after getting in is often to delete or edit logs. Hash-chaining makes that visible.

### 3.3 Detection Engine
Two complementary approaches:

| Approach | Strength | Example |
| --- | --- | --- |
| **Rules** | Near-zero false positives on well-known attacks | 20 failed logins in 10 seconds from one IP |
| **Machine learning** | Catches unknown / unusual behavior | A login at 3 AM from a new IP for a user who always logs in 9 to 6 |

**Rule examples**
```
IF failed_logins(user, 60s) >= 5          THEN raise(medium, brute_force)
IF failed_logins(ip, 10s)  >= 20          THEN raise(high, brute_force) -> Tier 1
IF process=powershell.exe
   AND parent NOT IN (explorer.exe, cmd.exe, known_admin_tools)
   AND cmdline CONTAINS (-enc, -EncodedCommand)
                                          THEN raise(high, living_off_the_land)
IF cmdline matches "vssadmin delete shadows" THEN raise(critical, ransomware_indicator)
```

**Baselining:** for each user/device the system keeps a rolling 30-day profile (e.g. login hours). A login 3+ standard deviations outside the normal range raises an anomaly score.

**Isolation Forest:** each session becomes a feature vector (login hour, source IP entropy, processes spawned, bytes sent/received). The model trains on recent *normal* sessions and scores new ones by how isolated (unusual) they are. Score above ~0.85 triggers a Tier 2 alert.

**Living-off-the-land (LOTL) detection:** flags abuse of legitimate Windows tools such as PowerShell, certutil, mshta, and wmic.

**Other detectors (later stages):** ransomware indicators (mass file renames, shadow copy deletion, honeytoken files), process hollowing/injection, DLL sideloading, YARA memory scanning, data exfiltration, credential stuffing, dormant account reactivation, service account misuse, threat-intel IP/domain reputation, CVE lookups against installed software.

### 3.4 Explainability
An alert is never just "Risk 82". It stores the contributing factors:

```
Risk 82. Flagged because:
 - Login at 3:14 AM (normally 9 AM to 6 PM)         weight 0.35
 - Source IP never seen before for this account     weight 0.30
 - 2 failed attempts in the last 5 minutes          weight 0.17
```
Admins can mark alerts as true or false positive; that **feedback loop** tunes thresholds and keeps the ML from being an unaccountable black box.

### 3.5 Response Engine (Tiered, not blind automation)

| Tier | Mode | When | Example |
| --- | --- | --- | --- |
| **1** | Automatic | High confidence, low collateral damage | Block IP after 20 failed logins in 10s; quarantine a file matching a known-malware hash |
| **2** | Human-confirmed | Medium confidence | Dashboard proposes "Block / Ignore / Investigate" and waits for one click |
| **3** | Alert only | Low confidence or informational | Login at an unusual hour with no other signal |

**Available actions:** block IP (Windows Firewall rule), disable a user account, kill a process, isolate the device from the network, quarantine files, force a session logoff.

**Why not full automation?** A false positive could lock out a legitimate user or kill a critical process. Mature commercial EDR tools follow the same philosophy: automate only what is cheap to be wrong about, keep a human in the loop for the rest.

**Safety mechanisms**
1. **Allowlist**: admin IPs, domain controllers, critical processes are never acted on automatically.
2. **Rate limiting**: prevents a false-positive storm from blocking a whole subnet.
3. **Dry-run mode**: logs "would have done X" without doing it (used to tune policy).
4. **One-click rollback**: remove the firewall rule, re-enable the account, restore the file.
5. **Full audit trail** of every automated action.
6. **Fail-safe**: if the agent or detection engine errors, nothing gets triggered.

**Decision flow**
```
on alert:
  tier = policy.lookup(alert)
  if target in allowlist  -> downgrade to Tier 3, log reason
  if tier == 1:
      if rate_limiter.allow() -> execute (or dry-run) and log
      else                    -> downgrade to Tier 2
  if tier == 2 -> create pending proposal, notify admin
  if tier == 3 -> notify only
```

### 3.6 Alerting and Case Management
- Risk-sorted alert queue; email / Slack / Telegram notifications.
- SMS or voice escalation for unresolved critical alerts.
- **Dead-man's switch**: if an endpoint goes silent, that itself raises an alert.
- Case tracking: open → investigating → resolved.
- Sensitivity levels, snooze/suppress rules, escalation rules.

### 3.7 Dashboard and Reporting
Screens:
- **Overview:** live alert feed, today's risk trend, top 5 issues to fix today.
- **Device view:** health, last heartbeat, open alerts per device.
- **Incident view:** one alert expanded into a timeline of related events before and after.
- **Reports:** daily/weekly PDF/HTML history, CSV/PDF export.
- **Admin:** users and roles, audit log, response-tier config, allowlist.
- **Self-health:** agent CPU/memory, DB size, last write, chain verification status.

**Daily report contents:** events processed, alerts by severity, automatic vs confirmed actions, top 5 riskiest devices/users, patches/software needed, each Tier 1 action with a one-line justification. Emailed automatically.

Optional: week-over-week trends, NIST CSF / ISO 27001 mapping, themes/accessibility, mobile push notifications.

### 3.8 Access Control and Admin Security
- Roles: **viewer** (read only) and **admin**.
- **Forced credential setup on first run**; there are no default credentials.
- MFA for dashboard login; session timeout with re-authentication for sensitive actions (disable account, isolate device, change allowlist).
- Encrypted configuration file; all admin actions audit-logged.

### 3.9 Agent Hardening
- Code-signed binaries and installer.
- Startup self-integrity check.
- Watchdog with auto-restart and suspicious-downtime flagging.
- Least-privilege service; only a separate Response worker holds elevated rights (firewall, accounts, processes).
- Anti-tamper protection against unauthorized stop/disable.

### 3.10 Extensibility
Plugin architecture for new detectors, a local REST API for alerts/status, and import of threat-intelligence feeds (STIX/TAXII).

---

## 4. What Gets Collected (and why)

| Source | Why it matters |
| --- | --- |
| Event Log / Sysmon | Core telemetry: logons, process creation, network connections |
| File integrity monitoring | Catches tampering with hosts file, startup folders, system binaries |
| Registry / persistence | Run keys, services, scheduled tasks are how malware survives reboot |
| Process lineage | Reveals chains like Word → PowerShell → unsigned binary |
| New accounts, drivers, BIOS/UEFI, hardware | Privilege escalation and persistence indicators |
| USB, clipboard, printer, Bluetooth | Physical and peripheral exfiltration paths |
| Firewall/AV status, software inventory, open ports | Configuration drift and hygiene checks |
| Network/DNS, VPN/Tor, cloud sync, saved-credential access, Hyper-V/WSL | Wider behavioral visibility |

---

## 5. Data Model (conceptual)

```
events  (id, timestamp, device_id, source, event_type, user, raw_payload, prev_hash, hash)
alerts  (id, event_ids, severity, risk_score, explanation, status, created_at)
actions (id, alert_id, tier, action_type, target, result, reversible, timestamp)
users   (id, username, role, mfa_enabled, last_login)
```
Also: allowlist, baselines, feedback, admin_audit.

---

## 6. End-to-End Example (Demo Scenario)

1. An attacker runs a brute-force script against the machine's login/RDP.
2. The agent logs each failed attempt (Event ID 4625) within seconds.
3. The rule engine sees **20 failures in 10 seconds** → raises a **Tier 1** alert.
4. The response engine checks the source IP against the **allowlist** (not present) and the **rate limiter** (allowed).
5. A **Windows Firewall block rule** is created for that IP.
6. The action is written to the **tamper-evident actions table** with justification.
7. The dashboard feed shows the block in real time; the admin gets an email/Slack message.
8. The daily report includes the incident, the detection evidence, and the action taken.
9. Running chain verification passes; manually editing a row makes it fail.

This single scenario exercises collection, detection, explainability, tiered response, tamper-evident logging, alerting, and reporting.

---

## 7. Technology Stack

| Layer | Technology |
| --- | --- |
| Desktop UI | WPF or WinUI 3 (.NET), or Tauri/Electron |
| Agent service | .NET 8 / C# Worker Service (Event Log, Sysmon, ETW) |
| Local storage | SQLite + SQLCipher |
| AI/ML | Python (scikit-learn, PyOD) as a local service, or ML.NET |
| Response | Windows Firewall API, PowerShell cmdlets |
| Reporting | ReportLab, WeasyPrint, or a .NET PDF library |
| Scheduling | Windows Task Scheduler / in-service timers |
| Packaging | MSIX or Inno Setup, code-signed |

**Processes:** Agent service, Response worker (privileged), Watchdog service, optional ML service (127.0.0.1), Dashboard app (talks to a localhost-only API).

---

## 8. Build Phases

| Scope | Contents | Difficulty | Time |
| --- | --- | --- | --- |
| **Minimal (MVP)** | Event Log monitoring, rule-based detection, simple dashboard, one auto-block scenario | ~4/10 | 2 to 4 weeks |
| **Phase 1** | Core detection (rules + Isolation Forest + baselining), hash-chained encrypted storage, Tier 1/2 response, agent hardening, full dashboard, alerting, daily report | ~6.5 to 7/10 | 2 to 4 months |
| **Full** | Everything listed in this guide | ~9.5/10 | Not realistically solo-feasible |

**Recommended order**
1. Lock the scope (Minimal → Phase 1 → Full).
2. Write a one-page threat model *before* code.
3. Build the Minimal version end to end and validate the architecture.
4. Expand toward Phase 1 once it works and is tested.

**Build order inside the project:**
Agent + Event Log → normalizer → SQLite → rules → alerts → firewall block (dry-run first) → API → dashboard → simulator → then hash chain, encryption, ML, hardening, reporting.

---

## 9. Testing and Demonstration
- **Attack simulation mode:** safe, local-only brute-force and port-scan triggers (labeled `simulated=true`).
- **EICAR test file** support for antivirus/quarantine testing.
- **Dry-run mode** for tuning the response layer.
- Key tests: Tier 1 block fires once, allowlist prevents block, rate limit caps blocks, editing/deleting a DB row breaks chain verification, killing the agent triggers watchdog restart, modified binary fails self-integrity check, rollback removes the firewall rule, viewer cannot perform admin actions.

---

## 10. Threat Model Summary

**In scope:** brute-force logins, port scans, persistence techniques, suspicious process chains, anomalous logins, connections to known-bad destinations, file tampering, LOTL abuse, common ransomware indicators, log tampering.

**Out of scope / not guaranteed:** zero-day exploits, kernel/firmware rootkits, a patient adversary evading baselines, misuse of legitimately stolen credentials, highly resourced targeted attacks.

**Assumed attacker:** starts as an unprivileged user or malware running as a standard user; may try to escalate, edit logs, or stop the agent. Kernel-level control and physical implants are not assumed.

**Threats to CyberSpy itself and mitigations**
| Threat | Mitigation |
| --- | --- |
| Log tampering | Hash chain, sealed head, periodic verification |
| Agent stopped | Watchdog, downtime flagging, service ACLs, dead-man's switch |
| Binary replaced | Code signing, startup integrity check |
| Credential theft / defaults | Forced first-run setup, hashed passwords, MFA |
| API abuse | Localhost only, token auth, RBAC |
| Self-DoS via spoofed events | Allowlist, rate limits, tiering |
| DB theft | SQLCipher, encrypted config, ACLs |
| ML poisoning | Reviewed feedback, rolling windows, drift monitoring |

---

## 11. Explicit Design Decisions

- **No true blockchain**: only local hash-chaining (distributed ledger, consensus, and mining were discussed and excluded).
- **Single endpoint first**: multi-device/distributed architecture is a future direction.
- **No full automation**: the tiered model was chosen deliberately for safety.
- **Rules first, ML second**: rules give reliable coverage of known attacks; ML adds coverage of the unknown after a 30-day baseline.
- **Untrusted input**: all event data is treated as untrusted (parameterized SQL, validated values before firewall commands, no string-built shell commands).

---

## 12. How It Fits Into Overall PC Security

CyberSpy AI is a **layer**, not a shield. Keep also:
- Windows Defender (or another AV) active and the OS updated
- A password manager and MFA on real accounts
- Regular backups (local or cloud)
- Caution with downloads, links, and attachments

CyberSpy AI adds visibility, early warning, a tamper-evident activity record, and some automated response on top of those fundamentals. It is accurately described as a hardened detection-and-response system for **known and common attack patterns** under a documented threat model, not an unbreakable system.

---

## 13. Glossary

| Term | Meaning |
| --- | --- |
| EDR | Endpoint Detection and Response |
| Sysmon | Microsoft tool that logs detailed process/network/file events |
| ETW | Event Tracing for Windows |
| Event ID 4625 | Windows "failed logon" event |
| LOTL | Living off the land: abusing legitimate system tools |
| Isolation Forest | ML algorithm that scores how unusual a data point is |
| Hash chain | Each log entry includes the hash of the previous one, so edits are detectable |
| SQLCipher | Encrypted SQLite |
| Allowlist | Targets that must never be acted on automatically |
| Dry-run | Simulate an action and log it without executing |
| Tier 1/2/3 | Auto action / human-confirmed / alert-only |
| STIX/TAXII | Standards for sharing threat intelligence |
| YARA | Pattern-matching rules for identifying malware |
