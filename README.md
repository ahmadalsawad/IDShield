# IDShield — Digital ID / Government Authentication Fraud Detector

An explainable, risk-based fraud-detection prototype for government digital-identity systems. Every authentication, registration, document-upload, and liveness-check event is scored by independent detectors and combined into a transparent decision (ALLOW / STEP-UP / BLOCK) with itemized evidence — never a bare score.

## Live demo (no setup required)

**https://idshield-demo.onrender.com**

| URL | What it is |
|---|---|
| `/` | Citizen-facing digital identity portal (sign in / register) |
| `/dashboard` | SOC / fraud-monitoring dashboard — live event feed, click any row for full evidence |
| `/attack-lab` | One-click scenario buttons, plus a "Try It Yourself" panel for uploading your own files — fires real HTTP traffic through the live pipeline |
| `/docs` | Interactive Swagger API documentation |

Hosted on Render's free tier: the instance sleeps after ~15 minutes of inactivity, so the first request after a period of no traffic can take 30–60 seconds to respond while it wakes up. Visit the URL a minute or two before a live demo. The database resets whenever the free instance restarts or sleeps — this is expected, not a bug; re-run the Attack Lab scenarios fresh for each demo session.

## Running it locally instead

### Requirements

- Python 3.10+
- No internet access needed at runtime (fully local, mock environment)

### Setup (run once)

```bash
cd IDShield
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run

```bash
uvicorn app:app --reload
```

Server starts at `http://127.0.0.1:8000`. Same URL paths as the live demo above (`/`, `/dashboard`, `/attack-lab`, `/docs`) apply locally too.

## Demo scenario (2 minutes, no setup beyond the above)

1. Open `/attack-lab`.
2. Click **RUN NORMAL USER** — a citizen registers, completes a liveness check, and logs in correctly. Check `/dashboard`: risk 0, ALLOW.
3. Click **RUN CREDENTIAL STUFFING** — ~45 rapid wrong-password login attempts fire against the live backend. Watch the log panel escalate from ALLOW to BLOCK as the pattern accumulates.
4. Click any of the other five scenario buttons (**SYNTHETIC IDENTITY**, **TAMPERED DOCUMENT**, **LIVENESS SPOOF**, **IMPOSSIBLE TRAVEL**, **DEVICE FARM**) — each fires genuine requests and produces a live, explainable decision.
5. Try the **"Try It Yourself"** panel at the bottom of the Attack Lab — upload your own photo or file through the same live document/liveness endpoints.
6. On `/dashboard`, click any row to open "Explain this decision" — shows every detector's score, confidence, and itemized evidence.

This works from a completely fresh database (none is included by default at first run — one is created automatically on server startup) and is safe to run repeatedly; re-running the same scenario just adds new, independent events.

## Statistical evaluation — all six detectors

Every detector now has a large-scale, reproducible, labeled-dataset evaluation, replayed through the live detector code (not a re-implementation):

| Detector | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Credential stuffing | 1.000 | 0.997 | 0.998 | 0.000 |
| Impossible travel | 1.000 | 0.920 | 0.958 | 0.000 |
| Device anomaly | 0.585 | 1.000 | 0.738 | 0.047 |
| Synthetic identity | 0.990 | 1.000 | 0.995 | 0.001 |
| Document forgery | 1.000 | 1.000 | 1.000 | 0.000 |
| Liveness check | 1.000 | 1.000 | 1.000 | 0.000 |

**Device anomaly's 0.585 precision is a real, disclosed finding, not an error**: it catches every synthetic device-farm attack (recall 1.000), but the 5-account trigger threshold sits exactly where some legitimately large households or shared kiosks land, producing real false positives. Raising the threshold or adding time-decay are the natural next steps — named explicitly rather than hidden.

To reproduce:

```bash
# Credential stuffing (5,750-event dataset)
python3 tests/synthetic_registry.py --count 2000 --seed 42
python3 tests/generate_labeled_dataset.py --seed 7
python3 tests/evaluate_credential_stuffing.py

# The other five detectors (2,500-3,400 events each)
python3 tests/evaluate_remaining_detectors.py --seed 11
```

Both are deterministic given the fixed seeds — rerunning reproduces every number above exactly.

## Project structure

```
IDShield/
├── app.py                  # FastAPI app: all routes and pipeline wiring
├── database.py              # SQLite engine (WAL mode) + session management
├── models.py                 # SQLAlchemy schema: users, events, detector results
├── risk_engine.py             # Combines detector outputs into ALLOW/STEP_UP/BLOCK
├── security.py                 # Password hashing (PBKDF2, stdlib only)
├── detectors/
│   ├── credential_stuffing.py   # Velocity, account diversity, failure rate, device reuse, IP reputation
│   ├── impossible_travel.py     # Haversine distance/velocity between logins
│   ├── device_anomaly.py        # Device-farm and new-device signals
│   ├── synthetic_identity.py    # Cross-record duplicate detection at registration
│   ├── document_fraud.py        # Document hash reuse, registry mismatch, EXIF metadata check
│   └── liveness_check.py        # Selfie reuse + simulated liveness failure
├── templates/               # dashboard.html, attack_lab.html, login.html
├── static/                     # style.css (shared theme for dashboard/attack lab)
├── tests/
│   ├── synthetic_registry.py         # Generates the fictional citizen registry
│   ├── generate_labeled_dataset.py    # Builds the 5,750-event credential-stuffing dataset
│   ├── evaluate_credential_stuffing.py # Statistical evaluation for credential stuffing
│   └── evaluate_remaining_detectors.py # Statistical evaluation for the other five detectors
├── data/                       # Generated citizen registry + labeled event dataset
└── runtime.txt                  # Pins Python 3.11 for deployment (Render compatibility)
```

## What is real vs. simulated

- **Real**: all detection logic, the risk engine, the database, every HTTP request the Attack Lab fires, and every statistical evaluation number above.
- **Simulated, by design**: source IP/device/location are supplied by the caller rather than derived from actual network infrastructure (there is no real distributed attacker environment); selfie liveness result is a caller-supplied flag standing in for a real biometric SDK; document/selfie "forgery" detection is limited to hash-reuse, registry mismatch, file-integrity, and EXIF-metadata checks — never a claim of forensic proof.
- **IP reputation, honestly scoped**: with no live threat-intelligence feed available, the reputation signal flags IP ranges reserved by RFC 5737 for documentation/testing only (192.0.2.0/24, 198.51.100.0/24) — traffic from these ranges should never appear in real production usage, so flagging it is a genuine anomaly signal, not a fabricated score.

## Known limitations

- Device anomaly's precision (0.585) is a real weakness, not yet fixed — see the evaluation table above.
- All evaluation datasets are self-generated using distributions we chose; a fully independent validation would need adversarially-generated or real-world attack data, which neither this prototype nor most published systems we reviewed have access to.
- Risk engine thresholds (0–29 / 30–69 / 70–100) are prototype defaults chosen for interpretability, not tuned against a cost-sensitive analysis of false-positive vs. false-negative impact.
- Document/liveness metadata checks (EXIF software tags) are a real but modest signal — not full forensic image analysis, which remains explicitly out of scope.
- No production-grade authentication/session security (this is a fraud-detection research prototype, not a hardened production auth system).
