"""
detectors/device_anomaly.py

WHAT THIS DETECTS — two independent, separately-scored signals:

1. DEVICE FARM PATTERN: one device_id authenticating as many distinct
   identities within a trailing window. Real users don't share a device
   fingerprint with dozens of other accounts; this pattern is typical of
   an attacker cycling through a stolen credential list on one physical
   or emulated device.

2. NEW-DEVICE-FOR-IDENTITY: this identity has prior login history, but
   NONE of it is from this device_id. This is a much weaker signal on its
   own (people genuinely do get new phones/laptops) — scored low, and
   explicitly documented as "one signal, not proof," per the project
   brief's instruction that device evidence must never be treated as
   absolute since client attributes can be spoofed.

These two signals are independent and can both fire on the same event
(e.g. a stolen device fingerprint reused for many accounts, one of which
also happens to be a first-time device for that particular account).
"""

from datetime import timedelta

DETECTOR_NAME = "device_anomaly"
DETECTOR_VERSION = "0.1.0"

FARM_WINDOW_SECONDS = 24 * 60 * 60  # 24 hours
FARM_THRESHOLDS = [(10, 30), (5, 15)]  # (unique identities on one device, points)

NEW_DEVICE_POINTS = 10

TRIGGER_THRESHOLD = 15


def _tiered_score(value, thresholds):
    for boundary, points in thresholds:
        if value >= boundary:
            return points
    return 0


def analyze(
    same_device_recent_usernames: set,
    user_has_prior_history: bool,
    user_has_used_this_device_before: bool,
) -> dict:
    """
    same_device_recent_usernames: set of distinct usernames that have
        authenticated (any outcome) from this device_id within the
        trailing FARM_WINDOW_SECONDS, INCLUDING the current attempt.
    user_has_prior_history: whether the current username has any prior
        AuthEvent at all (if not, "new device" is meaningless — everything
        is new on a first-ever login).
    user_has_used_this_device_before: whether any of the current user's
        PRIOR events used this same device_id.

    Returns the standard detector result dict.
    """
    evidence = []
    total_score = 0.0

    unique_identity_count = len(same_device_recent_usernames)
    farm_points = _tiered_score(unique_identity_count, FARM_THRESHOLDS)
    if farm_points:
        evidence.append({
            "label": f"{unique_identity_count} different accounts authenticated from this device in 24h",
            "value": unique_identity_count,
            "contribution": farm_points,
        })
        total_score += farm_points

    if user_has_prior_history and not user_has_used_this_device_before:
        evidence.append({
            "label": "Account authenticating from a device it has never used before",
            "value": True,
            "contribution": NEW_DEVICE_POINTS,
        })
        total_score += NEW_DEVICE_POINTS

    total_score = min(total_score, 100.0)

    # Confidence intentionally capped lower than credential_stuffing's —
    # device fingerprints are the weakest, most spoofable signal in the
    # system (see module docstring), so even a triggered result here
    # should carry less weight per point than a velocity-based detector.
    confidence = 0.6 if total_score > 0 else 0.3

    return {
        "detector": DETECTOR_NAME,
        "detector_version": DETECTOR_VERSION,
        "triggered": total_score >= TRIGGER_THRESHOLD,
        "score": total_score,
        "confidence": confidence,
        "evidence": evidence,
    }


def run(db, auth_event) -> dict:
    from models import AuthEvent

    window_start = auth_event.timestamp - timedelta(seconds=FARM_WINDOW_SECONDS)

    same_device_rows = (
        db.query(AuthEvent)
        .filter(AuthEvent.device_id == auth_event.device_id)
        .filter(AuthEvent.timestamp >= window_start)
        .filter(AuthEvent.timestamp <= auth_event.timestamp)
        .all()
    )
    same_device_usernames = {r.username_attempted for r in same_device_rows}

    user_has_prior_history = False
    user_has_used_this_device_before = False

    if auth_event.user_id is not None:
        prior_events = (
            db.query(AuthEvent)
            .filter(AuthEvent.user_id == auth_event.user_id)
            .filter(AuthEvent.id != auth_event.id)
            .filter(AuthEvent.timestamp < auth_event.timestamp)
            .all()
        )
        user_has_prior_history = len(prior_events) > 0
        user_has_used_this_device_before = any(
            e.device_id == auth_event.device_id for e in prior_events
        )

    return analyze(same_device_usernames, user_has_prior_history, user_has_used_this_device_before)


if __name__ == "__main__":
    import json

    # Device farm scenario: 12 distinct usernames from one device in 24h.
    farm_result = analyze(
        same_device_recent_usernames={f"user{i}" for i in range(12)},
        user_has_prior_history=False,
        user_has_used_this_device_before=False,
    )
    print("Device farm scenario:")
    print(json.dumps(farm_result, indent=2))
    assert farm_result["triggered"] is True

    # New device scenario: established user, device never seen before.
    new_device_result = analyze(
        same_device_recent_usernames={"citizen1"},
        user_has_prior_history=True,
        user_has_used_this_device_before=False,
    )
    print("\nNew device scenario:")
    print(json.dumps(new_device_result, indent=2))
    assert new_device_result["score"] == NEW_DEVICE_POINTS

    # Normal scenario: same user, same familiar device.
    normal_result = analyze(
        same_device_recent_usernames={"citizen1"},
        user_has_prior_history=True,
        user_has_used_this_device_before=True,
    )
    print("\nNormal scenario:")
    print(json.dumps(normal_result, indent=2))
    assert normal_result["triggered"] is False

    print("\nAll self-tests passed.")
