"""
detectors/credential_stuffing.py

WHAT THIS DETECTS
Credential stuffing = an attacker firing many login attempts, usually
against many different usernames, from a small number of sources/devices,
in a short time window. Classic signals: high attempt velocity, many
unique accounts targeted, high failure rate, low device diversity.

WHY IT'S SPLIT INTO analyze() + run()
`analyze()` is pure Python: it takes a plain list of dicts and a
reference timestamp, and returns a result. It has no dependency on
SQLAlchemy or FastAPI, so it can be unit-tested directly (see the
`if __name__ == "__main__"` block) and reused later by the offline
evaluation harness in Phase 8 without touching a real database.

`run()` is the thin adapter that pulls recent rows out of the DB and
hands them to analyze(). That's the only part that changes if we ever
swap SQLite for something else.

SCORING (prototype thresholds — see risk_engine.py docstring: these are
NOT scientifically validated, they're a defensible starting point to be
tuned against the Phase 8 labeled dataset).
"""

from datetime import timedelta

DETECTOR_NAME = "credential_stuffing"
DETECTOR_VERSION = "0.2.0"

WINDOW_SECONDS = 60

# Score weights, out of 100 total possible for this detector.
VELOCITY_THRESHOLDS = [(40, 30), (20, 20), (10, 10)]          # (attempts, points)
UNIQUE_USERNAME_THRESHOLDS = [(25, 20), (10, 12), (5, 6)]      # (unique usernames, points)
FAILURE_RATE_THRESHOLDS = [(0.8, 15), (0.5, 8)]                # (failure ratio, points)
SINGLE_DEVICE_MIN_ATTEMPTS = 10
SINGLE_DEVICE_POINTS = 10

# IP reputation, honestly scoped: we have no live threat-intelligence feed
# (no internet access, and no legitimate one exists for a prototype), so
# rather than fabricate a "reputation score," we flag traffic from IP
# ranges reserved by RFC 5737 for documentation/testing use only — these
# should NEVER appear in real production traffic, so seeing one genuinely
# is an anomaly signal, not an invented one. Scoped to the two ranges we
# have used consistently for simulated attacker traffic throughout this
# project (192.0.2.0/24, 198.51.100.0/24); 203.0.113.0/24 is deliberately
# excluded since it has also been used as a generic default/placeholder
# value elsewhere (e.g. the citizen portal's default IP field) and
# flagging it here would retroactively mislabel that legitimate-looking
# traffic.
REPUTATION_FLAGGED_PREFIXES = ("192.0.2.", "198.51.100.")
REPUTATION_FLAG_POINTS = 10

TRIGGER_THRESHOLD = 20  # detector reports triggered=True at/above this score


def _tiered_score(value, thresholds):
    """Return points for the highest threshold `value` meets, else 0."""
    for boundary, points in thresholds:
        if value >= boundary:
            return points
    return 0


def analyze(events: list[dict], now) -> dict:
    """
    events: list of dicts, each with keys:
        username (str), source_ip (str), device_id (str),
        success (bool), timestamp (datetime)
    now: the datetime to treat as "current time" (usually the incoming
         event's own timestamp) — passed explicitly rather than calling
         datetime.now() so this function is deterministic and testable.

    Returns the standard detector result dict (see detectors/__init__.py).
    """
    window_start = now - timedelta(seconds=WINDOW_SECONDS)
    recent = [e for e in events if window_start <= e["timestamp"] <= now]

    attempt_count = len(recent)
    unique_usernames = len({e["username"] for e in recent})
    unique_devices = len({e["device_id"] for e in recent})
    failure_count = sum(1 for e in recent if not e["success"])
    failure_ratio = (failure_count / attempt_count) if attempt_count else 0.0

    evidence = []
    total_score = 0.0

    pts = _tiered_score(attempt_count, VELOCITY_THRESHOLDS)
    if pts:
        evidence.append({
            "label": f"{attempt_count} login attempts within {WINDOW_SECONDS} seconds",
            "value": attempt_count,
            "contribution": pts,
        })
        total_score += pts

    pts = _tiered_score(unique_usernames, UNIQUE_USERNAME_THRESHOLDS)
    if pts:
        evidence.append({
            "label": f"{unique_usernames} different accounts targeted",
            "value": unique_usernames,
            "contribution": pts,
        })
        total_score += pts

    pts = _tiered_score(failure_ratio, FAILURE_RATE_THRESHOLDS)
    if pts:
        evidence.append({
            "label": f"{failure_count}/{attempt_count} attempts failed "
                     f"({failure_ratio:.0%} failure rate)",
            "value": round(failure_ratio, 2),
            "contribution": pts,
        })
        total_score += pts

    if unique_devices == 1 and attempt_count >= SINGLE_DEVICE_MIN_ATTEMPTS:
        evidence.append({
            "label": f"All {attempt_count} attempts came from a single device",
            "value": 1,
            "contribution": SINGLE_DEVICE_POINTS,
        })
        total_score += SINGLE_DEVICE_POINTS

    # IP reputation: check the CURRENT event's own source IP (not any IP
    # that happens to appear in the window's history) against the
    # documentation-range list above. See the module-level comment for
    # why this stays honestly scoped rather than claiming a real feed.
    current_matches = [e for e in recent if e["timestamp"] == now]
    current_ip = current_matches[0]["source_ip"] if current_matches else None
    if current_ip and any(current_ip.startswith(p) for p in REPUTATION_FLAGGED_PREFIXES):
        evidence.append({
            "label": f"Source IP {current_ip} falls within a reputation-flagged range "
                     f"(reserved documentation/test range — never expected in real traffic)",
            "value": current_ip,
            "contribution": REPUTATION_FLAG_POINTS,
        })
        total_score += REPUTATION_FLAG_POINTS

    total_score = min(total_score, 100.0)

    # Confidence scales with how much data backed the decision — five
    # attempts in the window is weaker evidence than fifty, even if both
    # happened to cross a scoring threshold.
    confidence = min(0.5 + (attempt_count / 100), 0.98) if attempt_count else 0.3

    return {
        "detector": DETECTOR_NAME,
        "detector_version": DETECTOR_VERSION,
        "triggered": total_score >= TRIGGER_THRESHOLD,
        "score": total_score,
        "confidence": round(confidence, 2),
        "evidence": evidence,
    }


def run(db, auth_event) -> dict:
    """
    DB-backed wrapper. Pulls every AuthEvent in the last WINDOW_SECONDS
    that shares the same source_ip OR the same device_id as `auth_event`,
    then delegates to analyze().

    Sharing IP OR device (not AND) matters: an attacker can rotate one
    while keeping the other fixed, and we still want to catch it.
    """
    from models import AuthEvent  # local import avoids a circular import at module load

    window_start = auth_event.timestamp - timedelta(seconds=WINDOW_SECONDS)

    rows = (
        db.query(AuthEvent)
        .filter(AuthEvent.timestamp >= window_start)
        .filter(AuthEvent.timestamp <= auth_event.timestamp)
        .filter(
            (AuthEvent.source_ip == auth_event.source_ip)
            | (AuthEvent.device_id == auth_event.device_id)
        )
        .all()
    )

    events = [
        {
            "username": r.username_attempted,
            "source_ip": r.source_ip,
            "device_id": r.device_id,
            "success": r.success,
            "timestamp": r.timestamp,
        }
        for r in rows
    ]

    return analyze(events, now=auth_event.timestamp)


if __name__ == "__main__":
    # Quick self-test matching the example evidence from the project brief:
    # 47 attempts / 60 seconds, 31 unique accounts, 45 failures, 1 device.
    from datetime import datetime, timezone

    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    test_events = []
    for i in range(47):
        test_events.append({
            "username": f"citizen{i % 31}",
            "source_ip": "203.0.113.9",
            "device_id": "device-fixed-001",
            "success": i >= 45,  # only the last 2 succeed -> 45 failures
            "timestamp": base_time + timedelta(seconds=i),
        })

    result = analyze(test_events, now=base_time + timedelta(seconds=46))
    import json
    print(json.dumps(result, indent=2))

    assert result["triggered"] is True, "Expected this scenario to trigger"
    assert result["score"] >= 70, f"Expected high score, got {result['score']}"

    # New: IP reputation signal, tested in isolation. A single legitimate
    # login from a flagged documentation-range IP should get the weak
    # +10 signal but NOT trigger alone; the same single login from a
    # normal private IP should get nothing.
    single_event_flagged_ip = [{
        "username": "citizen1", "source_ip": "198.51.100.9", "device_id": "device-1",
        "success": True, "timestamp": base_time,
    }]
    flagged_result = analyze(single_event_flagged_ip, now=base_time)
    print("\nSingle legit-looking login from a flagged IP range:")
    print(json.dumps(flagged_result, indent=2))
    assert flagged_result["triggered"] is False
    assert flagged_result["score"] == REPUTATION_FLAG_POINTS
    assert any("reputation-flagged" in e["label"] for e in flagged_result["evidence"])

    single_event_normal_ip = [{
        "username": "citizen1", "source_ip": "10.0.0.5", "device_id": "device-1",
        "success": True, "timestamp": base_time,
    }]
    normal_result = analyze(single_event_normal_ip, now=base_time)
    assert normal_result["score"] == 0.0

    print("\nAll self-tests passed.")
