"""
app.py

Phase 1 goal: prove the full pipeline works end to end on ONE detector
before adding the other four.

    Login request
        -> AuthEvent logged (Event Collection)
        -> credential_stuffing detector runs against real DB history
        -> risk_engine combines detector output(s)
        -> AuthEvent updated with risk_score + decision
        -> full explainable JSON returned to caller

Phase 3 added impossible_travel and device_anomaly to the login pipeline.
Phase 4 added a parallel registration pipeline for synthetic_identity.
Phase 5 (this revision) adds a document-upload pipeline for document_fraud.

REVISION NOTE — tamper-evident audit chain (see audit_chain.py, and the
chain_hash column added to models.py): every *DetectorResult row created
anywhere in this file now gets a chain_hash computed from the previous
row in its own table plus its own decision-relevant fields, BEFORE it is
added to the session. See _next_chain_hash() below and its four call
sites (register, login, document upload, liveness check).

Deliberately NOT yet built: dashboard UI, attack lab UI. Those come in
later phases per the roadmap.

HOW TO RUN LOCALLY:
    pip install -r requirements.txt
    uvicorn app:app --reload
    open http://127.0.0.1:8000/docs   <- interactive API testing (Swagger UI)
"""

import hashlib
import io
import os
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db, init_db
from models import (
    User, AuthEvent, DetectorResult,
    RegistrationEvent, IdentityDetectorResult,
    DocumentUpload, DocumentDetectorResult,
    LivenessCheck, LivenessDetectorResult,
)
from security import hash_password, verify_password
from detectors import credential_stuffing, impossible_travel, device_anomaly, synthetic_identity, document_fraud, liveness_check
import risk_engine
from audit_chain import compute_record_hash, verify_chain, GENESIS_HASH
import json

app = FastAPI(title="IDShield", version="0.1.0")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

UPLOAD_DIR = "uploads"


@app.on_event("startup")
def on_startup():
    init_db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)


def _next_chain_hash(db: Session, model_class, new_fields: dict) -> str:
    """Tamper-evident audit chain (audit_chain.py): look up the latest
    chain_hash already committed for this *DetectorResult table, and
    compute the hash the NEW row should carry. Call this once per result
    row, right before constructing it, so every row is born with its
    chain_hash already set. When creating several rows for the same
    table in a loop (see /login below), commit each row before computing
    the next one's hash — otherwise two rows could both compute against
    the same stale "latest row" and the chain would be wrong."""
    last = db.query(model_class).order_by(model_class.id.desc()).first()
    prev_hash = last.chain_hash if (last and last.chain_hash) else GENESIS_HASH
    return compute_record_hash(prev_hash, new_fields)


# ---------------------------------------------------------------------------
# Request/response schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=256)

    # Phase 4 identity fields — all optional so a bare-minimum registration
    # (as used in Phases 1-3 testing) still works. synthetic_identity simply
    # skips whatever checks a missing field would require.
    full_name: str | None = None
    date_of_birth: str | None = None  # "YYYY-MM-DD"
    phone_number: str | None = None
    national_id: str | None = None
    document_type: str | None = None
    document_number: str | None = None
    address_emirate: str | None = None
    address_street: str | None = None
    address_building: str | None = None
    document_issue_date: str | None = None  # "YYYY-MM-DD"
    document_expiry_date: str | None = None  # "YYYY-MM-DD"

    # Device/IP used to submit THIS registration — same simulated-field
    # rationale as LoginRequest's source_ip/device_id.
    registered_device_id: str | None = None
    registered_ip: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str
    # In a real system these come from the request/connection itself
    # (client IP, device fingerprinting library). In this mock/demo
    # environment we accept them explicitly so the Attack Lab (Phase 7)
    # can simulate many distinct synthetic sources and devices without
    # needing real distributed infrastructure. This is a deliberate,
    # documented simplification — call it out in your report.
    source_ip: str = Field(default="127.0.0.1")
    device_id: str = Field(default="unknown-device")

    # Simulated geolocation, same rationale as source_ip/device_id above —
    # optional so existing callers (and the Phase 1 test page) keep working
    # unchanged; impossible_travel simply can't evaluate an event missing
    # these.
    latitude: float | None = Field(default=None)
    longitude: float | None = Field(default=None)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/attack-lab", response_class=HTMLResponse)
def attack_lab_page(request: Request):
    return templates.TemplateResponse("attack_lab.html", {"request": request})


@app.post("/register", status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        date_of_birth=payload.date_of_birth,
        phone_number=payload.phone_number,
        national_id=payload.national_id,
        document_type=payload.document_type,
        document_number=payload.document_number,
        address_emirate=payload.address_emirate,
        address_street=payload.address_street,
        address_building=payload.address_building,
        document_issue_date=payload.document_issue_date,
        document_expiry_date=payload.document_expiry_date,
        registered_device_id=payload.registered_device_id,
        registered_ip=payload.registered_ip,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Phase 4: evaluate the new identity against the existing registry
    # BEFORE returning — this is the "Registration -> Event -> Synthetic-
    # identity detection -> Risk engine -> decision" path from the brief.
    reg_event = RegistrationEvent(user_id=user.id, timestamp=datetime.now(timezone.utc))
    db.add(reg_event)
    db.commit()
    db.refresh(reg_event)

    identity_result = synthetic_identity.run(db, user)
    identity_outcome = risk_engine.combine([identity_result])

    reg_event.risk_score = identity_outcome["risk_score"]
    reg_event.decision = identity_outcome["decision"]
    db.commit()

    identity_fields = {
        "detector_name": identity_result["detector"],
        "detector_version": identity_result["detector_version"],
        "triggered": identity_result["triggered"],
        "score": identity_result["score"],
        "confidence": identity_result["confidence"],
        "evidence_json": json.dumps(identity_result["evidence"]),
    }
    db.add(IdentityDetectorResult(
        registration_event_id=reg_event.id,
        chain_hash=_next_chain_hash(db, IdentityDetectorResult, identity_fields),
        **identity_fields,
    ))
    db.commit()

    return {
        "id": user.id,
        "username": user.username,
        "registration_event_id": reg_event.event_id,
        "identity_risk_score": identity_outcome["risk_score"],
        "identity_decision": identity_outcome["decision"],  # ALLOW / STEP_UP (manual review) / BLOCK (reject)
        "detector_results": [identity_result],
    }


@app.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    password_ok = bool(user) and verify_password(payload.password, user.password_hash)

    # Log the event FIRST, regardless of outcome. Credential stuffing
    # detection depends on seeing failed attempts against usernames that
    # may not even exist — if we only logged successes, this detector
    # would be blind to the exact pattern it exists to catch.
    event = AuthEvent(
        user_id=user.id if user else None,
        username_attempted=payload.username,
        source_ip=payload.source_ip,
        device_id=payload.device_id,
        success=password_ok,
        timestamp=datetime.now(timezone.utc),
        latitude=payload.latitude,
        longitude=payload.longitude,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # Run detectors. Phase 1 has exactly one; the list structure is what
    # lets Phases 3-5 slot in impossible_travel, device_anomaly,
    # synthetic_identity, and document_fraud without changing this loop.
    detector_modules = [credential_stuffing, impossible_travel, device_anomaly]
    detector_results = [module.run(db, event) for module in detector_modules]

    outcome = risk_engine.combine(detector_results)

    event.risk_score = outcome["risk_score"]
    event.decision = outcome["decision"]
    db.commit()

    # Chain-hash each row as it's created, committing one at a time so
    # each subsequent row's _next_chain_hash sees the previous row's
    # already-committed hash rather than a stale "latest row" — see
    # _next_chain_hash's docstring for why this matters when several
    # rows land in the same table back-to-back.
    for result in detector_results:
        fields = {
            "detector_name": result["detector"],
            "detector_version": result["detector_version"],
            "triggered": result["triggered"],
            "score": result["score"],
            "confidence": result["confidence"],
            "evidence_json": json.dumps(result["evidence"]),
        }
        db.add(DetectorResult(
            auth_event_id=event.id,
            chain_hash=_next_chain_hash(db, DetectorResult, fields),
            **fields,
        ))
        db.commit()

    return {
        "event_id": event.event_id,
        "username_attempted": event.username_attempted,
        "password_correct": password_ok,
        "risk_score": outcome["risk_score"],
        "decision": outcome["decision"],
        "detector_results": detector_results,
    }


@app.get("/events/{event_id}")
def explain_event(event_id: str, db: Session = Depends(get_db)):
    """'Explain this decision' — the SOC dashboard (Phase 6) will call this."""
    event = db.query(AuthEvent).filter(AuthEvent.event_id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    results = db.query(DetectorResult).filter(DetectorResult.auth_event_id == event.id).all()

    return {
        "event_id": event.event_id,
        "username_attempted": event.username_attempted,
        "source_ip": event.source_ip,
        "device_id": event.device_id,
        "success": event.success,
        "timestamp": event.timestamp.isoformat(),
        "risk_score": event.risk_score,
        "decision": event.decision,
        "detector_results": [
            {
                "detector": r.detector_name,
                "detector_version": r.detector_version,
                "triggered": r.triggered,
                "score": r.score,
                "confidence": r.confidence,
                "evidence": json.loads(r.evidence_json),
            }
            for r in results
        ],
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/registrations/{event_id}")
def explain_registration(event_id: str, db: Session = Depends(get_db)):
    """'Explain this decision' for identity onboarding, mirroring /events/{id}."""
    reg_event = db.query(RegistrationEvent).filter(RegistrationEvent.event_id == event_id).first()
    if not reg_event:
        raise HTTPException(status_code=404, detail="Registration event not found")

    results = db.query(IdentityDetectorResult).filter(
        IdentityDetectorResult.registration_event_id == reg_event.id
    ).all()

    return {
        "event_id": reg_event.event_id,
        "user_id": reg_event.user_id,
        "timestamp": reg_event.timestamp.isoformat(),
        "risk_score": reg_event.risk_score,
        "decision": reg_event.decision,
        "detector_results": [
            {
                "detector": r.detector_name,
                "detector_version": r.detector_version,
                "triggered": r.triggered,
                "score": r.score,
                "confidence": r.confidence,
                "evidence": json.loads(r.evidence_json),
            }
            for r in results
        ],
    }


# ---------------------------------------------------------------------------
# Phase 5: document upload / document_fraud
# ---------------------------------------------------------------------------

ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg", "image/jpg"}


def _is_valid_image(raw_bytes: bytes) -> bool:
    """Best-effort check that the uploaded bytes are a real, readable image.
    Uses Pillow if available; falls back to a permissive True (rather than
    silently failing the whole upload) if Pillow isn't installed, since
    file-integrity is one signal among several, not a hard gate."""
    try:
        from PIL import Image
        Image.open(io.BytesIO(raw_bytes)).verify()
        return True
    except ImportError:
        return True
    except Exception:
        return False


def _extract_exif_software(raw_bytes: bytes) -> str | None:
    """Reads the real EXIF 'Software' tag from an image file, if present.
    Returns None if the file has no EXIF data, the tag is absent, or the
    file can't be parsed — never raises, since this is a corroborating
    signal, not a hard gate (see document_fraud.py's module docstring for
    why this stays a disclosed metadata check, not a forensic claim)."""
    try:
        from PIL import Image, ExifTags
        img = Image.open(io.BytesIO(raw_bytes))
        exif = img.getexif()
        if not exif:
            return None
        for tag_id, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, tag_id)
            if tag_name == "Software" and value:
                return str(value)
        return None
    except Exception:
        return None


@app.post("/documents/upload")
async def upload_document(
    username: str = Form(...),
    declared_full_name: str | None = Form(default=None),
    declared_document_number: str | None = Form(default=None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported content type: {file.content_type}")

    raw_bytes = await file.read()
    file_hash = hashlib.sha256(raw_bytes).hexdigest()
    is_valid_image = _is_valid_image(raw_bytes)
    exif_software = _extract_exif_software(raw_bytes)

    # Store under a hash-derived filename to avoid collisions/overwrites
    # and to make "is this the same file as that other upload" trivially
    # verifiable by filename alone during a jury Q&A.
    stored_filename = f"{file_hash}_{uuid.uuid4().hex[:8]}{os.path.splitext(file.filename or '')[1]}"
    stored_path = os.path.join(UPLOAD_DIR, stored_filename)
    with open(stored_path, "wb") as f:
        f.write(raw_bytes)

    user = db.query(User).filter(User.username == username).first()

    doc = DocumentUpload(
        user_id=user.id if user else None,
        username_submitted=username,
        original_filename=file.filename or "unknown",
        stored_path=stored_path,
        file_hash_sha256=file_hash,
        file_size_bytes=len(raw_bytes),
        declared_full_name=declared_full_name,
        declared_document_number=declared_document_number,
        timestamp=datetime.now(timezone.utc),
    )
    doc._is_valid_image = is_valid_image  # transient attribute, read by document_fraud.run() before commit
    doc._exif_software = exif_software  # transient attribute, read by document_fraud.run() before commit
    db.add(doc)
    db.commit()
    db.refresh(doc)

    result = document_fraud.run(db, doc)
    outcome = risk_engine.combine([result])

    doc.risk_score = outcome["risk_score"]
    doc.decision = outcome["decision"]
    db.commit()

    document_fields = {
        "detector_name": result["detector"],
        "detector_version": result["detector_version"],
        "triggered": result["triggered"],
        "score": result["score"],
        "confidence": result["confidence"],
        "evidence_json": json.dumps(result["evidence"]),
    }
    db.add(DocumentDetectorResult(
        document_upload_id=doc.id,
        chain_hash=_next_chain_hash(db, DocumentDetectorResult, document_fields),
        **document_fields,
    ))
    db.commit()

    return {
        "event_id": doc.event_id,
        "username_submitted": doc.username_submitted,
        "file_hash_sha256": doc.file_hash_sha256,
        "risk_score": outcome["risk_score"],
        "decision": outcome["decision"],
        "classification": result["classification"],
        "detector_results": [result],
    }


@app.get("/documents/{event_id}")
def explain_document(event_id: str, db: Session = Depends(get_db)):
    doc = db.query(DocumentUpload).filter(DocumentUpload.event_id == event_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document event not found")

    results = db.query(DocumentDetectorResult).filter(
        DocumentDetectorResult.document_upload_id == doc.id
    ).all()

    return {
        "event_id": doc.event_id,
        "username_submitted": doc.username_submitted,
        "original_filename": doc.original_filename,
        "file_hash_sha256": doc.file_hash_sha256,
        "timestamp": doc.timestamp.isoformat(),
        "risk_score": doc.risk_score,
        "decision": doc.decision,
        "detector_results": [
            {
                "detector": r.detector_name,
                "detector_version": r.detector_version,
                "triggered": r.triggered,
                "score": r.score,
                "confidence": r.confidence,
                "evidence": json.loads(r.evidence_json),
            }
            for r in results
        ],
    }


# ---------------------------------------------------------------------------
# Selfie / liveness step — the missing piece of the onboarding flow:
# document upload -> selfie/liveness check -> login. See
# detectors/liveness_check.py for what's real vs. simulated here.
# ---------------------------------------------------------------------------

@app.post("/liveness/check")
async def submit_liveness_check(
    username: str = Form(...),
    simulated_liveness_passed: bool = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported content type: {file.content_type}")

    raw_bytes = await file.read()
    file_hash = hashlib.sha256(raw_bytes).hexdigest()
    is_valid_image = _is_valid_image(raw_bytes)

    user = db.query(User).filter(User.username == username).first()

    check = LivenessCheck(
        user_id=user.id if user else None,
        username_submitted=username,
        selfie_file_hash=file_hash,
        selfie_file_size_bytes=len(raw_bytes),
        simulated_liveness_passed=simulated_liveness_passed,
        timestamp=datetime.now(timezone.utc),
    )
    check._is_valid_image = is_valid_image  # transient, read by liveness_check.run() before commit
    db.add(check)
    db.commit()
    db.refresh(check)

    result = liveness_check.run(db, check)
    outcome = risk_engine.combine([result])

    check.risk_score = outcome["risk_score"]
    check.decision = outcome["decision"]
    db.commit()

    liveness_fields = {
        "detector_name": result["detector"],
        "detector_version": result["detector_version"],
        "triggered": result["triggered"],
        "score": result["score"],
        "confidence": result["confidence"],
        "evidence_json": json.dumps(result["evidence"]),
    }
    db.add(LivenessDetectorResult(
        liveness_check_id=check.id,
        chain_hash=_next_chain_hash(db, LivenessDetectorResult, liveness_fields),
        **liveness_fields,
    ))
    db.commit()

    return {
        "event_id": check.event_id,
        "username_submitted": check.username_submitted,
        "simulated_liveness_passed": check.simulated_liveness_passed,
        "risk_score": outcome["risk_score"],
        "decision": outcome["decision"],
        "classification": result["classification"],
        "detector_results": [result],
    }


@app.get("/liveness/{event_id}")
def explain_liveness(event_id: str, db: Session = Depends(get_db)):
    check = db.query(LivenessCheck).filter(LivenessCheck.event_id == event_id).first()
    if not check:
        raise HTTPException(status_code=404, detail="Liveness event not found")

    results = db.query(LivenessDetectorResult).filter(
        LivenessDetectorResult.liveness_check_id == check.id
    ).all()

    return {
        "event_id": check.event_id,
        "username_submitted": check.username_submitted,
        "simulated_liveness_passed": check.simulated_liveness_passed,
        "timestamp": check.timestamp.isoformat(),
        "risk_score": check.risk_score,
        "decision": check.decision,
        "detector_results": [
            {
                "detector": r.detector_name,
                "detector_version": r.detector_version,
                "triggered": r.triggered,
                "score": r.score,
                "confidence": r.confidence,
                "evidence": json.loads(r.evidence_json),
            }
            for r in results
        ],
    }


# ---------------------------------------------------------------------------
# Phase 6: SOC / Fraud Dashboard data endpoints
# ---------------------------------------------------------------------------
# These endpoints exist purely to feed dashboard.html. They read data that
# was already written by the three pipelines above — the dashboard never
# computes or alters a risk decision, it only visualizes what the real
# pipeline already decided. This matters for the jury story: nothing here
# is "for display purposes only" data, it's the same rows /events/{id} etc.
# already expose, just aggregated.

@app.get("/api/summary")
def api_summary(db: Session = Depends(get_db)):
    def _counts(model):
        total = db.query(model).count()
        allow = db.query(model).filter(model.decision == "ALLOW").count()
        step_up = db.query(model).filter(model.decision == "STEP_UP").count()
        block = db.query(model).filter(model.decision == "BLOCK").count()
        return {"total": total, "allow": allow, "step_up": step_up, "block": block}

    return {
        "logins": _counts(AuthEvent),
        "registrations": _counts(RegistrationEvent),
        "documents": _counts(DocumentUpload),
        "liveness_checks": _counts(LivenessCheck),
    }


@app.get("/api/recent-events")
def api_recent_events(limit: int = 50, db: Session = Depends(get_db)):
    """Unified, chronological feed across all three pipelines, for the
    dashboard's main table. Each row carries enough info to render + a
    (type, event_id) pair the frontend uses to fetch full evidence from
    the matching /events, /registrations, or /documents explain endpoint."""
    rows = []

    for e in db.query(AuthEvent).order_by(AuthEvent.timestamp.desc()).limit(limit).all():
        rows.append({
            "type": "login",
            "event_id": e.event_id,
            "identity": e.username_attempted,
            "timestamp": e.timestamp.isoformat(),
            "risk_score": e.risk_score,
            "decision": e.decision,
            "detail": f"{e.source_ip} / {e.device_id}",
        })

    for r in db.query(RegistrationEvent).order_by(RegistrationEvent.timestamp.desc()).limit(limit).all():
        user = db.query(User).filter(User.id == r.user_id).first()
        rows.append({
            "type": "registration",
            "event_id": r.event_id,
            "identity": user.username if user else f"user#{r.user_id}",
            "timestamp": r.timestamp.isoformat(),
            "risk_score": r.risk_score,
            "decision": r.decision,
            "detail": "new identity registration",
        })

    for d in db.query(DocumentUpload).order_by(DocumentUpload.timestamp.desc()).limit(limit).all():
        rows.append({
            "type": "document",
            "event_id": d.event_id,
            "identity": d.username_submitted,
            "timestamp": d.timestamp.isoformat(),
            "risk_score": d.risk_score,
            "decision": d.decision,
            "detail": d.original_filename,
        })

    for l in db.query(LivenessCheck).order_by(LivenessCheck.timestamp.desc()).limit(limit).all():
        rows.append({
            "type": "liveness",
            "event_id": l.event_id,
            "identity": l.username_submitted,
            "timestamp": l.timestamp.isoformat(),
            "risk_score": l.risk_score,
            "decision": l.decision,
            "detail": f"simulated liveness: {'PASS' if l.simulated_liveness_passed else 'FAIL'}",
        })

    rows.sort(key=lambda r: r["timestamp"], reverse=True)
    return rows[:limit]


# ---------------------------------------------------------------------------
# Phase 7 (this revision): live audit-chain verification & demo
#
# These two endpoints make the tamper-evident hash chain (audit_chain.py,
# see also the "Tamper-evident audit chain" paragraph in the report)
# something a jury member can click, not just read about. /status is a
# genuine, read-only check against whatever is really in the database
# right now. /demo-tamper deliberately does what an insider with raw DB
# access could otherwise do silently — edit a past decision's evidence
# after the fact, without recomputing chain_hash — purely so that act
# and its detection are both visible live. It would not exist in a real
# deployment; it exists here so this claim is checkable, not asserted.
# ---------------------------------------------------------------------------

CHAINED_MODELS = {
    "detector_results": DetectorResult,
    "identity_detector_results": IdentityDetectorResult,
    "document_detector_results": DocumentDetectorResult,
    "liveness_detector_results": LivenessDetectorResult,
}


@app.get("/api/audit-chain/status")
def audit_chain_status(db: Session = Depends(get_db)):
    """Recomputes every chained row's hash from genesis forward, for all
    four result tables, using whatever is actually in the database at
    the moment this is called. Never writes anything."""
    tables_status = {}
    overall_valid = True

    for table_name, model_class in CHAINED_MODELS.items():
        rows = db.query(model_class).order_by(model_class.id.asc()).all()
        row_dicts = [{
            "id": r.id,
            "detector_name": r.detector_name,
            "detector_version": r.detector_version,
            "triggered": r.triggered,
            "score": r.score,
            "confidence": r.confidence,
            "evidence_json": r.evidence_json,
            "chain_hash": r.chain_hash,
        } for r in rows]

        # Rows written before this revision have chain_hash=NULL and
        # aren't part of the chain — verify only from the first row that
        # actually has one.
        first_chained = next((i for i, row in enumerate(row_dicts) if row["chain_hash"]), None)
        if first_chained is None:
            tables_status[table_name] = {"valid": True, "checked": 0, "break_at_id": None, "note": "no chained rows yet"}
            continue

        result = verify_chain(row_dicts[first_chained:])
        tables_status[table_name] = {
            "valid": result["valid"],
            "checked": result["checked"],
            "break_at_id": result["break_at_id"],
            "note": None,
        }
        overall_valid = overall_valid and result["valid"]

    return {"overall_valid": overall_valid, "tables": tables_status}


@app.post("/api/audit-chain/demo-tamper")
def audit_chain_demo_tamper(table: str = "detector_results", db: Session = Depends(get_db)):
    """DEMO-ONLY: edits the most recent row in the given table's
    evidence_json directly, deliberately WITHOUT recomputing chain_hash —
    exactly what an insider with raw DB access, and no knowledge of the
    chain, could otherwise do silently. Call /api/audit-chain/status
    right after this to watch it get caught."""
    if table not in CHAINED_MODELS:
        raise HTTPException(status_code=400, detail=f"Unknown table: {table}. Choose one of {list(CHAINED_MODELS)}")
    model_class = CHAINED_MODELS[table]

    row = db.query(model_class).order_by(model_class.id.desc()).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"No rows in {table} yet — run an Attack Lab scenario first")

    original_evidence = json.loads(row.evidence_json)
    tampered_evidence = [{"label": "DEMO: this evidence was quietly edited after the fact", "value": None, "contribution": 0}]
    row.evidence_json = json.dumps(tampered_evidence)
    db.commit()

    return {
        "tampered_table": table,
        "tampered_row_id": row.id,
        "original_evidence": original_evidence,
        "new_evidence": tampered_evidence,
    }
