# IDShield — Digital ID / Government Authentication Fraud Detector

An explainable, risk-based fraud-detection prototype for government digital-identity systems. Every authentication, registration, document-upload, and liveness-check event is scored by independent detectors and combined into a transparent decision (ALLOW / STEP-UP / BLOCK) with itemized evidence — never a bare score.

## Requirements

- Python 3.10+
- No internet access needed at runtime (fully local, mock environment)

## Setup (run once)

```bash
cd IDShield
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app:app --reload
```

Server starts at `http://127.0.0.1:8000`. Open in a browser:

| URL | What it is |
|---|---|
| `/dashboard` | SOC / fraud-monitoring dashboard — live event feed, click any row for full evidence |
| `/attack-lab` | One-click scenario buttons — fires real HTTP traffic through the live pipeline |
| `/docs` | Interactive Swagger API documentation |
| `/` | Minimal manual login test page |

## Demo scenario (2 minutes, no setup beyond the above)

1. Open `/attack-lab`.
2. Click **RUN NORMAL USER** — a citizen registers, completes a liveness check, and logs in correctly. Check `/dashboard`: risk 0, ALLOW.
3. Click **RUN CREDENTIAL STUFFING** — ~45 rapid wrong-password login attempts fire against the live backend. Watch the log panel escalate from ALLOW to BLOCK as the pattern accumulates.
4. Click any of the other four scenario buttons (**SYNTHETIC IDENTITY**, **TAMPERED DOCUMENT**, **IMPOSSIBLE TRAVEL**, **DEVICE FARM**, **LIVENESS SPOOF**) — each fires genuine requests and produces a live, explainable decision.
5. On `/dashboard`, click any row to open "Explain this decision" — shows every detector's score, confidence, and itemized evidence.

This works from a completely fresh database (none is included by default at first run — one is created automatically on server startup) and is safe to run repeatedly; re-running the same scenario just adds new, independent events.

## Regenerating the statistical evaluation (optional)

The credential-stuffing detector is validated against a large synthetic labeled dataset. To reproduce:

```bash
python3 tests/synthetic_registry.py --count 2000 --seed 42
python3 tests/generate_labeled_dataset.py --seed 7
python3 tests/evaluate_credential_stuffing.py
```

Expected output (deterministic given the fixed seeds): Precision 1.0, Recall 0.9263, F1 0.9617, False Positive Rate 0.0, 30/30 attack campaigns detected across 5,750 labeled events.

## Project structure

```
IDShield/
├── app.py                  # FastAPI app: all routes and pipeline wiring
├── database.py              # SQLite engine (WAL mode) + session management
├── models.py                 # SQLAlchemy schema: users, events, detector results
├── risk_engine.py             # Combines detector outputs into ALLOW/STEP_UP/BLOCK
├── security.py                 # Password hashing (PBKDF2, stdlib only)
├── detectors/
│   ├── credential_stuffing.py   # Velocity, account diversity, failure rate, device reuse
│   ├── impossible_travel.py     # Haversine distance/velocity between logins
│   ├── device_anomaly.py        # Device-farm and new-device signals
│   ├── synthetic_identity.py    # Cross-record duplicate detection at registration
│   ├── document_fraud.py        # Document hash reuse + registry mismatch
│   └── liveness_check.py        # Selfie reuse + simulated liveness failure
├── templates/               # dashboard.html, attack_lab.html, login.html
├── tests/                    # Synthetic data generation + offline evaluation
└── data/                       # Generated citizen registry + labeled event dataset
```

## What is real vs. simulated

- **Real**: all detection logic, the risk engine, the database, every HTTP request the Attack Lab fires, and the statistical evaluation numbers above.
- **Simulated, by design**: source IP/device/location are supplied by the caller rather than derived from actual network infrastructure (there is no real distributed attacker environment); selfie liveness result is a caller-supplied flag standing in for a real biometric SDK; document/selfie "forgery" detection is limited to hash-reuse, registry mismatch, and file-integrity checks — never a claim of forensic proof.

## Known limitations

- Full statistical evaluation (precision/recall/F1 on a large labeled dataset) currently covers only the credential-stuffing detector. The other five detectors are validated via real, targeted scenarios (see Attack Lab) rather than large-scale statistics.
- Risk engine thresholds (0–29 / 30–69 / 70–100) are prototype defaults chosen for interpretability, not tuned against a cost-sensitive analysis.
- No production-grade authentication/session security (this is a fraud-detection research prototype, not a hardened production auth system).
