"""
detectors/liveness_check.py

WHAT THIS DETECTS
This fills the missing "selfie/liveness" stage of the onboarding flow:
document upload -> selfie/liveness check -> login. Real biometric liveness
detection (distinguishing a live face from a photo, video replay, or mask)
requires specialized models and hardware this prototype does not have —
exactly the same reasoning that kept document_fraud from claiming
forensic image analysis. So, consistent with that precedent:

The caller supplies `simulated_liveness_passed`, standing in for what a
real liveness SDK would return (this is what the competition brief calls
out as explicitly acceptable: "can be simulated"). What this detector adds
on top of that raw flag is genuine, verifiable analysis:

1. SIMULATED LIVENESS FAILURE — the supplied result itself says the check
   failed (a simulated spoof: photo-of-a-photo, replayed video, etc.).
   This is the detector directly trusting the upstream signal, the same
   way a real system would react to its liveness SDK's verdict.

2. REUSED SELFIE ACROSS IDENTITIES — the exact same selfie image (by
   SHA-256 hash) was already submitted under a DIFFERENT username. There
   is no legitimate reason two different citizens submit the identical
   photo; this is a strong signal of a stolen or fabricated identity photo
   being reused, independent of whatever the liveness flag says.

3. FILE INTEGRITY ANOMALY — same check as document_fraud: the file isn't
   a valid, readable image or has an implausible size for a selfie.

As with document_fraud, this NEVER claims a "proven" spoof — only that
liveness indicators were detected, for a human to review.
"""

DETECTOR_NAME = "liveness_check"
DETECTOR_VERSION = "0.1.0"

POINTS_SIMULATED_FAILURE = 50
POINTS_REUSED_SELFIE = 40
POINTS_FILE_INTEGRITY = 15

TRIGGER_THRESHOLD = 20

MIN_PLAUSIBLE_BYTES = 2 * 1024
MAX_PLAUSIBLE_BYTES = 15 * 1024 * 1024


def analyze(candidate: dict, prior_selfies: list[dict]) -> dict:
    """
    candidate: dict with keys:
        file_hash (str), file_size_bytes (int), is_valid_image (bool),
        simulated_liveness_passed (bool), username (str)
    prior_selfies: list of dicts, each with keys file_hash, username —
        every OTHER previously submitted selfie, any user.

    Returns the standard detector result dict.
    """
    evidence = []
    total_score = 0.0

    if not candidate.get("simulated_liveness_passed", True):
        evidence.append({
            "label": "LIVENESS INDICATOR: simulated liveness check reported failure (possible spoof/replay)",
            "value": False,
            "contribution": POINTS_SIMULATED_FAILURE,
        })
        total_score += POINTS_SIMULATED_FAILURE

    reused = [
        s for s in prior_selfies
        if s["file_hash"] == candidate["file_hash"] and s["username"] != candidate["username"]
    ]
    if reused:
        other_usernames = sorted({s["username"] for s in reused})
        evidence.append({
            "label": (
                f"LIVENESS INDICATOR: identical selfie image previously "
                f"submitted under different account(s): {other_usernames}"
            ),
            "value": candidate["file_hash"],
            "contribution": POINTS_REUSED_SELFIE,
        })
        total_score += POINTS_REUSED_SELFIE

    size = candidate.get("file_size_bytes", 0)
    implausible_size = size < MIN_PLAUSIBLE_BYTES or size > MAX_PLAUSIBLE_BYTES
    not_a_valid_image = not candidate.get("is_valid_image", False)
    if implausible_size or not_a_valid_image:
        reasons = []
        if not_a_valid_image:
            reasons.append("file is not a readable image")
        if implausible_size:
            reasons.append(f"implausible file size ({size} bytes)")
        evidence.append({
            "label": f"File integrity anomaly: {', '.join(reasons)}",
            "value": {"size_bytes": size, "is_valid_image": candidate.get("is_valid_image", False)},
            "contribution": POINTS_FILE_INTEGRITY,
        })
        total_score += POINTS_FILE_INTEGRITY

    total_score = min(total_score, 100.0)
    confidence = 0.9 if reused or not candidate.get("simulated_liveness_passed", True) else (0.6 if evidence else 0.3)

    return {
        "detector": DETECTOR_NAME,
        "detector_version": DETECTOR_VERSION,
        "triggered": total_score >= TRIGGER_THRESHOLD,
        "score": total_score,
        "confidence": confidence,
        "evidence": evidence,
        "classification": "LIVENESS_INDICATORS_DETECTED" if total_score >= TRIGGER_THRESHOLD else "NO_INDICATORS_DETECTED",
    }


def run(db, liveness_check) -> dict:
    from models import LivenessCheck

    prior_rows = (
        db.query(LivenessCheck)
        .filter(LivenessCheck.id != liveness_check.id)
        .all()
    )
    prior_selfies = [{"file_hash": r.selfie_file_hash, "username": r.username_submitted} for r in prior_rows]

    candidate = {
        "file_hash": liveness_check.selfie_file_hash,
        "file_size_bytes": liveness_check.selfie_file_size_bytes,
        "is_valid_image": getattr(liveness_check, "_is_valid_image", True),
        "simulated_liveness_passed": liveness_check.simulated_liveness_passed,
        "username": liveness_check.username_submitted,
    }

    return analyze(candidate, prior_selfies)


if __name__ == "__main__":
    import json

    prior = [{"file_hash": "selfie123", "username": "real_citizen"}]

    # Reused selfie under a different account, and a simulated spoof failure.
    fraud_candidate = {
        "file_hash": "selfie123",
        "file_size_bytes": 500_000,
        "is_valid_image": True,
        "simulated_liveness_passed": False,
        "username": "synthetic_fake",
    }
    result = analyze(fraud_candidate, prior)
    print("Reused selfie + simulated spoof failure:")
    print(json.dumps(result, indent=2))
    assert result["triggered"] is True
    assert result["score"] == 90  # 50 + 40

    # Clean case: new selfie, liveness passed, valid image.
    clean_candidate = {
        "file_hash": "selfie456",
        "file_size_bytes": 500_000,
        "is_valid_image": True,
        "simulated_liveness_passed": True,
        "username": "real_citizen",
    }
    clean_result = analyze(clean_candidate, prior)
    print("\nClean selfie:")
    print(json.dumps(clean_result, indent=2))
    assert clean_result["triggered"] is False

    print("\nAll self-tests passed.")
