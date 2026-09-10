"""
detectors/impossible_travel.py

WHAT THIS DETECTS
Two logins for the SAME account, at two different locations, close enough
together in time that traveling between them would require an impossible
speed. Classic case from the project brief: Dubai at 10:00, London at
10:15 — ~5,500 km in 15 minutes, i.e. ~22,000 km/h. No commercial or
military transport does that, so this is a strong signal of account
takeover (attacker logging in from a different location than the real
account holder).

WHY HAVERSINE
The Haversine formula computes great-circle distance between two
lat/lon points on a sphere. It's the standard, simple, well-understood
choice for this kind of check — accurate to within ~0.5% for Earth-scale
distances, and easy to defend to a jury asking "how did you calculate
that number."

THRESHOLDS (prototype, same caveat as risk_engine.py: not scientifically
validated, chosen for interpretability):
    > 1000 km/h  -> IMPOSSIBLE tier (faster than any commercial flight)
    500-1000 km/h -> SUSPICIOUS tier (physically possible only by fast
                     direct flight with zero ground/airport time — still
                     worth flagging, at lower confidence)
    < 500 km/h    -> not flagged
"""

import math
from datetime import timedelta

DETECTOR_NAME = "impossible_travel"
DETECTOR_VERSION = "0.1.0"

EARTH_RADIUS_KM = 6371.0

IMPOSSIBLE_VELOCITY_KMH = 1000.0
SUSPICIOUS_VELOCITY_KMH = 500.0

IMPOSSIBLE_POINTS = 40
SUSPICIOUS_POINTS = 20

TRIGGER_THRESHOLD = 20

# Floor on elapsed time used in the velocity calculation, to avoid a
# near-zero denominator producing a meaningless/infinite speed for two
# events that land at (almost) the same timestamp. This does NOT hide the
# case — two same-second logins from different continents still produce a
# huge, correctly-flagged velocity, it just avoids a divide-by-zero crash.
MIN_ELAPSED_HOURS = 1.0 / 3600  # 1 second, expressed in hours


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return EARTH_RADIUS_KM * c


def analyze(previous_event: dict | None, current_event: dict) -> dict:
    """
    previous_event / current_event: dicts with keys
        latitude (float), longitude (float), timestamp (datetime), location_label (str, optional)
    previous_event may be None (user's first-ever located login — nothing
    to compare against, so this detector can't say anything).

    Returns the standard detector result dict.
    """
    evidence = []
    score = 0.0
    confidence = 0.5

    if previous_event is None or current_event.get("latitude") is None or current_event.get("longitude") is None:
        return {
            "detector": DETECTOR_NAME,
            "detector_version": DETECTOR_VERSION,
            "triggered": False,
            "score": 0.0,
            "confidence": 0.3,
            "evidence": [],
        }

    distance_km = haversine_km(
        previous_event["latitude"], previous_event["longitude"],
        current_event["latitude"], current_event["longitude"],
    )

    elapsed = current_event["timestamp"] - previous_event["timestamp"]
    elapsed_hours = max(elapsed.total_seconds() / 3600.0, MIN_ELAPSED_HOURS)

    required_velocity_kmh = distance_km / elapsed_hours

    if required_velocity_kmh > IMPOSSIBLE_VELOCITY_KMH:
        score = IMPOSSIBLE_POINTS
        confidence = 0.95
        tier = "IMPOSSIBLE"
    elif required_velocity_kmh > SUSPICIOUS_VELOCITY_KMH:
        score = SUSPICIOUS_POINTS
        confidence = 0.7
        tier = "SUSPICIOUS"
    else:
        tier = None

    if tier:
        prev_label = previous_event.get("location_label", f"({previous_event['latitude']:.2f}, {previous_event['longitude']:.2f})")
        curr_label = current_event.get("location_label", f"({current_event['latitude']:.2f}, {current_event['longitude']:.2f})")
        evidence.append({
            "label": (
                f"{tier}: {prev_label} -> {curr_label}, "
                f"{distance_km:.0f} km in {elapsed.total_seconds()/60:.1f} min "
                f"(requires {required_velocity_kmh:,.0f} km/h)"
            ),
            "value": {
                "distance_km": round(distance_km, 1),
                "elapsed_minutes": round(elapsed.total_seconds() / 60, 1),
                "required_velocity_kmh": round(required_velocity_kmh, 1),
            },
            "contribution": score,
        })

    return {
        "detector": DETECTOR_NAME,
        "detector_version": DETECTOR_VERSION,
        "triggered": score >= TRIGGER_THRESHOLD,
        "score": score,
        "confidence": confidence,
        "evidence": evidence,
    }


def run(db, auth_event) -> dict:
    """
    DB-backed wrapper. Finds this user's most recent PRIOR located event
    (any success/fail status — even a failed attempt reveals where a login
    was tried from) and compares it against the current one.
    """
    from models import AuthEvent

    if auth_event.user_id is None:
        # No known account -> nothing to compare travel history against.
        return analyze(None, {
            "latitude": auth_event.latitude,
            "longitude": auth_event.longitude,
            "timestamp": auth_event.timestamp,
        })

    previous = (
        db.query(AuthEvent)
        .filter(AuthEvent.user_id == auth_event.user_id)
        .filter(AuthEvent.id != auth_event.id)
        .filter(AuthEvent.timestamp < auth_event.timestamp)
        .filter(AuthEvent.latitude.isnot(None))
        .filter(AuthEvent.longitude.isnot(None))
        .order_by(AuthEvent.timestamp.desc())
        .first()
    )

    previous_dict = None
    if previous is not None:
        previous_dict = {
            "latitude": previous.latitude,
            "longitude": previous.longitude,
            "timestamp": previous.timestamp,
        }

    current_dict = {
        "latitude": auth_event.latitude,
        "longitude": auth_event.longitude,
        "timestamp": auth_event.timestamp,
    }

    return analyze(previous_dict, current_dict)


if __name__ == "__main__":
    from datetime import datetime, timezone
    import json

    dubai = {"latitude": 25.2048, "longitude": 55.2708, "timestamp": datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc), "location_label": "Dubai"}
    london = {"latitude": 51.5074, "longitude": -0.1278, "timestamp": datetime(2026, 1, 1, 10, 15, tzinfo=timezone.utc), "location_label": "London"}

    result = analyze(dubai, london)
    print(json.dumps(result, indent=2))

    assert result["triggered"] is True
    assert result["evidence"][0]["value"]["distance_km"] > 5000
    print("\nSelf-test passed.")
