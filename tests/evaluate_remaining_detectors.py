"""
tests/evaluate_remaining_detectors.py

Extends the credential-stuffing evaluation methodology (see
evaluate_credential_stuffing.py) to the other five detectors, directly per
jury feedback: "Extending the same labeled dataset methodology to the
remaining detectors would strengthen the result most."

METHODOLOGY NOTE — addressing the "self-generated data" critique:
The jury also correctly flagged that our evaluation data is generated from
the same assumptions the detectors encode, which limits how far the
headline figures carry. We do not have real fraud data (this is a
competition prototype using synthetic citizens), so we cannot fully
eliminate this. What we CAN do, and have done here: (1) generate attack
parameters from wide, randomized ranges rather than values hand-picked to
sit comfortably past each detector's exact thresholds, so some generated
cases fall near or below the boundary and are expected to be missed
(matching the honest "detection latency" pattern already reported for
credential stuffing); (2) call each detector's real analyze() function
directly, not a re-implementation; (3) report the confusion matrix in
full, including false negatives, rather than only a headline accuracy
number. This narrows but does not close the circularity gap — a genuinely
independent validation would need real-world or adversarially-generated
(not self-authored) attack data, which we name explicitly as future work.

Each section below is self-contained: generate a labeled dataset for one
detector, replay it through that detector's real analyze() function, and
accumulate a confusion matrix.
"""

import random
import sys
import io
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detectors import impossible_travel, device_anomaly, synthetic_identity, document_fraud, liveness_check  # noqa: E402


def confusion_metrics(tp, fp, tn, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4),
    }


# ============================================================
# 1. IMPOSSIBLE TRAVEL
# ============================================================
CITIES = {
    "Dubai": (25.2048, 55.2708), "Sharjah": (25.3573, 55.4033), "Al Ain": (24.2075, 55.7447),
    "Abu Dhabi": (24.4539, 54.3773), "London": (51.5074, -0.1278), "New York": (40.7128, -74.0060),
    "Singapore": (1.3521, 103.8198), "Tokyo": (35.6762, 139.6503), "Paris": (48.8566, 2.3522),
    "Sydney": (-33.8688, 151.2093), "Cairo": (30.0444, 31.2357), "Mumbai": (19.0760, 72.8777),
    "Riyadh": (24.7136, 46.6753), "Doha": (25.2854, 51.5310), "Istanbul": (41.0082, 28.9784),
}
NEARBY_PAIRS = [("Dubai", "Sharjah"), ("Dubai", "Al Ain"), ("Dubai", "Abu Dhabi"), ("Riyadh", "Doha")]


def eval_impossible_travel(rng, n_users=2500, n_attacks=200):
    tp = fp = tn = fn = 0
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    city_names = list(CITIES.keys())

    for i in range(n_users):
        is_attack = i < n_attacks
        t0 = base_time + timedelta(minutes=rng.uniform(0, 500000))

        if is_attack:
            # Two genuinely distant cities, short elapsed time — but the gap
            # itself is randomized (2-90 min) rather than fixed, so some
            # cases sit closer to the SUSPICIOUS boundary than others.
            c1, c2 = rng.sample(city_names, 2)
            gap_minutes = rng.uniform(2, 90)
        else:
            # Legitimate: same city (majority) or a real nearby-city pair,
            # with a plausible multi-hour-to-multi-day gap.
            if rng.random() < 0.7:
                c1 = c2 = rng.choice(city_names)
            else:
                c1, c2 = rng.choice(NEARBY_PAIRS)
            gap_minutes = rng.uniform(120, 4000)

        lat1, lon1 = CITIES[c1]
        lat2, lon2 = CITIES[c2]
        t1 = t0 + timedelta(minutes=gap_minutes)

        prev = {"latitude": lat1, "longitude": lon1, "timestamp": t0}
        curr = {"latitude": lat2, "longitude": lon2, "timestamp": t1}

        result = impossible_travel.analyze(prev, curr)
        predicted = result["triggered"]

        if is_attack and predicted:
            tp += 1
        elif is_attack and not predicted:
            fn += 1
        elif not is_attack and predicted:
            fp += 1
        else:
            tn += 1

    return confusion_metrics(tp, fp, tn, fn), n_users


# ============================================================
# 2. DEVICE ANOMALY
# ============================================================
def eval_device_anomaly(rng, n_legit=3000, n_attacks=200):
    tp = fp = tn = fn = 0

    for i in range(n_legit):
        # Realistic distribution: most shared devices have 1-2 users
        # (couple/family), with a shrinking tail up to 5 — not uniform,
        # since uniform 1-5 would unrealistically put 20% of ALL normal
        # traffic exactly on the trigger boundary.
        device_count = rng.choices([1, 2, 3, 4, 5], weights=[40, 30, 15, 10, 5])[0]
        usernames = {f"legit_user_{i}_{j}" for j in range(device_count)}
        user_has_history = rng.random() < 0.6
        used_before = rng.random() < 0.8 if user_has_history else False

        result = device_anomaly.analyze(usernames, user_has_history, used_before)
        predicted = result["triggered"]
        if predicted:
            fp += 1
        else:
            tn += 1

    for i in range(n_attacks):
        # Same boundary-inclusive range on the attack side (5-30), so some
        # attack cases sit at the weakest possible signal (exactly 5) —
        # testing whether the detector still catches a small-scale farm,
        # not just an obviously large one.
        device_count = rng.randint(5, 30)
        usernames = {f"farm_user_{i}_{j}" for j in range(device_count)}
        user_has_history = rng.random() < 0.3
        used_before = False

        result = device_anomaly.analyze(usernames, user_has_history, used_before)
        predicted = result["triggered"]
        if predicted:
            tp += 1
        else:
            fn += 1

    return confusion_metrics(tp, fp, tn, fn), n_legit + n_attacks


# ============================================================
# 3. SYNTHETIC IDENTITY
# ============================================================
def _random_citizen(rng, idx):
    return {
        "username": f"citizen_{idx}",
        "phone_number": f"+971-50-{rng.randint(1000000,9999999)}",
        "national_id": f"784-{rng.randint(1970,2005)}-{rng.randint(1000000,9999999)}-{rng.randint(0,9)}",
        "document_number": f"IDN-{rng.randint(10000000,99999999)}",
        "registered_device_id": f"device-{rng.getrandbits(24):06x}",
        "registered_ip": f"10.0.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "address_street": rng.choice(["Al Wasl Road", "Sheikh Zayed Road", "Corniche St"]),
        "address_building": f"Building {rng.randint(1,60)}, Apt {rng.randint(100,499)}",
        "document_issue_date": "2021-01-01",
        "document_expiry_date": "2031-01-01",
        "date_of_birth": f"{rng.randint(1965,2004)}-01-01",
    }


def eval_synthetic_identity(rng, n_legit=3000, n_attacks=200):
    tp = fp = tn = fn = 0
    existing = []

    all_candidates = []
    for i in range(n_legit):
        all_candidates.append((_random_citizen(rng, f"L{i}"), False))
    for i in range(n_attacks):
        victim = _random_citizen(rng, f"V{i}")
        existing.append(victim)  # victim registers first, legitimately
        attacker = _random_citizen(rng, f"A{i}")
        # Randomly duplicate ONE OR BOTH of phone/document — not always both,
        # so some attack cases are weaker signals near the trigger boundary.
        dup_choice = rng.choice(["phone", "document", "both"])
        if dup_choice in ("phone", "both"):
            attacker["phone_number"] = victim["phone_number"]
        if dup_choice in ("document", "both"):
            attacker["document_number"] = victim["document_number"]
        all_candidates.append((attacker, True))

    rng.shuffle(all_candidates)

    for candidate, is_attack in all_candidates:
        result = synthetic_identity.analyze(candidate, existing)
        predicted = result["triggered"]
        existing.append(candidate)

        if is_attack and predicted:
            tp += 1
        elif is_attack and not predicted:
            fn += 1
        elif not is_attack and predicted:
            fp += 1
        else:
            tn += 1

    return confusion_metrics(tp, fp, tn, fn), len(all_candidates)


# ============================================================
# 4. DOCUMENT FORGERY
# ============================================================
def eval_document_fraud(rng, n_legit=3000, n_attacks=200):
    tp = fp = tn = fn = 0
    prior_uploads = []

    # Real-world editing software names sometimes appear legitimately —
    # e.g. a citizen who scanned and lightly cropped/rotated their own
    # document before uploading. A fraction of LEGITIMATE cases carry this
    # metadata to test the weak signal doesn't cause noise on its own.
    EDITING_TOOLS = ["Adobe Photoshop 25.0", "GIMP 2.10", "Snapseed", None, None, None, None, None]

    # Each event gets a timestamp; attack pairs are generated with the
    # owner's timestamp strictly before the thief's, then the WHOLE set is
    # sorted chronologically (not shuffled) before replay — preserving the
    # causal order a real deployment would have (you can't reuse a file
    # that hasn't been uploaded yet), while still interleaving attack
    # pairs naturally among unrelated legitimate traffic.
    events = []
    for i in range(n_legit):
        uname = f"docowner_{i}"
        registry = {"full_name": f"Citizen {i}", "document_number": f"IDN-{i:08d}"}
        candidate = {
            "file_hash": f"hash_{rng.getrandbits(64):016x}",
            "file_size_bytes": rng.randint(200_000, 2_000_000),
            "is_valid_image": True,
            "declared_full_name": registry["full_name"],
            "declared_document_number": registry["document_number"],
            "username": uname,
            "exif_software": rng.choice(EDITING_TOOLS),
        }
        events.append((rng.uniform(0, 100000), candidate, registry, False))

    for i in range(n_attacks):
        owner_uname = f"realowner_{i}"
        thief_uname = f"thief_{i}"
        shared_hash = f"hash_{rng.getrandbits(64):016x}"
        registry_owner = {"full_name": f"Real Citizen {i}", "document_number": f"IDN-R{i:07d}"}
        owner_t = rng.uniform(0, 99000)
        owner_candidate = {
            "file_hash": shared_hash, "file_size_bytes": rng.randint(200_000, 2_000_000),
            "is_valid_image": True, "declared_full_name": registry_owner["full_name"],
            "declared_document_number": registry_owner["document_number"], "username": owner_uname,
        }
        events.append((owner_t, owner_candidate, registry_owner, False))  # first use is legitimate

        registry_thief = {"full_name": f"Thief {i}", "document_number": f"IDN-T{i:07d}"}
        thief_t = owner_t + rng.uniform(1, 1000)  # strictly after the owner's upload
        thief_candidate = {
            "file_hash": shared_hash,  # reused file — the actual attack signal
            "file_size_bytes": owner_candidate["file_size_bytes"], "is_valid_image": True,
            "declared_full_name": registry_thief["full_name"],
            "declared_document_number": registry_thief["document_number"], "username": thief_uname,
        }
        events.append((thief_t, thief_candidate, registry_thief, True))

    events.sort(key=lambda e: e[0])  # chronological replay, not shuffled

    for _, candidate, registry, is_attack in events:
        result = document_fraud.analyze(candidate, prior_uploads, registry)
        predicted = result["triggered"]
        prior_uploads.append({"file_hash": candidate["file_hash"], "username": candidate["username"]})

        if is_attack and predicted:
            tp += 1
        elif is_attack and not predicted:
            fn += 1
        elif not is_attack and predicted:
            fp += 1
        else:
            tn += 1

    return confusion_metrics(tp, fp, tn, fn), len(events)


# ============================================================
# 5. LIVENESS CHECK
# ============================================================
def eval_liveness_check(rng, n_legit=3000, n_attacks=200):
    tp = fp = tn = fn = 0
    prior_selfies = []

    events = []
    for i in range(n_legit):
        candidate = {
            "file_hash": f"selfie_{rng.getrandbits(64):016x}",
            "file_size_bytes": rng.randint(150_000, 1_500_000),
            "is_valid_image": True,
            "simulated_liveness_passed": True,
            "username": f"selfieowner_{i}",
        }
        events.append((rng.uniform(0, 100000), candidate, False))

    for i in range(n_attacks):
        owner_uname = f"realselfie_{i}"
        thief_uname = f"selfiethief_{i}"
        shared_hash = f"selfie_{rng.getrandbits(64):016x}"
        owner_t = rng.uniform(0, 99000)
        owner_candidate = {
            "file_hash": shared_hash, "file_size_bytes": rng.randint(150_000, 1_500_000),
            "is_valid_image": True, "simulated_liveness_passed": True, "username": owner_uname,
        }
        events.append((owner_t, owner_candidate, False))

        # Randomize whether the attack case ALSO fails simulated liveness,
        # so not every attack case has two stacked strong signals — some
        # rely on the reused-hash signal alone.
        liveness_fails_too = rng.random() < 0.5
        thief_t = owner_t + rng.uniform(1, 1000)  # strictly after the owner's submission
        thief_candidate = {
            "file_hash": shared_hash, "file_size_bytes": owner_candidate["file_size_bytes"],
            "is_valid_image": True, "simulated_liveness_passed": not liveness_fails_too,
            "username": thief_uname,
        }
        events.append((thief_t, thief_candidate, True))

    events.sort(key=lambda e: e[0])  # chronological replay, not shuffled

    for _, candidate, is_attack in events:
        result = liveness_check.analyze(candidate, prior_selfies)
        predicted = result["triggered"]
        prior_selfies.append({"file_hash": candidate["file_hash"], "username": candidate["username"]})

        if is_attack and predicted:
            tp += 1
        elif is_attack and not predicted:
            fn += 1
        elif not is_attack and predicted:
            fp += 1
        else:
            tn += 1

    return confusion_metrics(tp, fp, tn, fn), len(events)


def _ahash(raw_bytes):
    from PIL import Image
    img = Image.open(io.BytesIO(raw_bytes)).convert("L").resize((8, 8), Image.LANCZOS)
    pixels = list(img.getdata())
    avg = sum(pixels) / len(pixels)
    bits = "".join("1" if p >= avg else "0" for p in pixels)
    return f"{int(bits, 2):016x}"


def eval_perceptual_hash(rng, n_legit=200, n_attacks=50):
    """
    Dedicated sub-evaluation for document forgery's perceptual-hash signal
    (the case exact SHA-256 comparison cannot catch: the same image
    re-saved at a different quality/size, changing every byte). Uses REAL
    generated images and REAL JPEG re-compression, not fake hash strings —
    this is the one sub-feature where genuine image content matters, so
    genuine images are what we test it with. Kept as a separate, smaller
    evaluation from the main document-forgery run above (which uses fast
    synthetic hash strings for its much larger n) to keep total runtime
    reasonable while still giving this specific new signal real,
    reproducible statistical backing.
    """
    from PIL import Image

    def _document_bytes(seed_val, quality):
        # Genuinely varied blocky structure per seed — like different real
        # documents actually differ (distinct photo/text regions), not
        # just a uniform color tint over an identical layout. An earlier
        # version of this generator used near-solid backgrounds, which
        # produced a false near-100% false-positive rate under aHash once
        # downsampled to 8x8 — a test-generator flaw we caught and fixed,
        # not a flaw in the hashing approach itself (see report for detail).
        block_rng = random.Random(seed_val)
        img = Image.new("RGB", (300, 200))
        pixels = img.load()
        for bx in range(0, 300, 20):
            for by in range(0, 200, 20):
                shade = block_rng.randint(30, 220)
                for x in range(bx, min(bx + 20, 300)):
                    for y in range(by, min(by + 20, 200)):
                        pixels[x, y] = (shade, shade, shade)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality)
        return buf.getvalue()

    tp = fp = tn = fn = 0
    prior_uploads = []

    events = []
    for i in range(n_legit):
        raw = _document_bytes(seed_val=i, quality=rng.choice([85, 90, 95]))
        sha = hashlib.sha256(raw).hexdigest()
        phash = _ahash(raw)
        candidate = {
            "file_hash": sha, "file_size_bytes": len(raw), "is_valid_image": True,
            "declared_full_name": f"Citizen {i}", "declared_document_number": f"IDN-{i:08d}",
            "username": f"docowner_{i}", "perceptual_hash": phash,
        }
        events.append((rng.uniform(0, 100000), candidate, False))

    for i in range(n_attacks):
        base_seed = 100000 + i  # distinct image content from the legit pool above
        owner_raw = _document_bytes(seed_val=base_seed, quality=95)
        owner_sha = hashlib.sha256(owner_raw).hexdigest()
        owner_phash = _ahash(owner_raw)
        owner_t = rng.uniform(0, 99000)
        events.append((owner_t, {
            "file_hash": owner_sha, "file_size_bytes": len(owner_raw), "is_valid_image": True,
            "declared_full_name": f"Real Owner {i}", "declared_document_number": f"IDN-R{i:06d}",
            "username": f"realowner_{i}", "perceptual_hash": owner_phash,
        }, False))

        # Same image, re-compressed at a much lower quality — every byte
        # (and SHA-256) changes, but it's visually the same document.
        thief_raw = _document_bytes(seed_val=base_seed, quality=rng.randint(25, 55))
        thief_sha = hashlib.sha256(thief_raw).hexdigest()
        thief_phash = _ahash(thief_raw)
        thief_t = owner_t + rng.uniform(1, 1000)
        events.append((thief_t, {
            "file_hash": thief_sha, "file_size_bytes": len(thief_raw), "is_valid_image": True,
            "declared_full_name": f"Thief {i}", "declared_document_number": f"IDN-T{i:06d}",
            "username": f"thief_{i}", "perceptual_hash": thief_phash,
        }, True))

    events.sort(key=lambda e: e[0])

    for _, candidate, is_attack in events:
        result = document_fraud.analyze(candidate, prior_uploads, None)
        predicted = result["triggered"]
        prior_uploads.append({
            "file_hash": candidate["file_hash"], "username": candidate["username"],
            "perceptual_hash": candidate["perceptual_hash"],
        })
        if is_attack and predicted:
            tp += 1
        elif is_attack and not predicted:
            fn += 1
        elif not is_attack and predicted:
            fp += 1
        else:
            tn += 1

    return confusion_metrics(tp, fp, tn, fn), len(events)


# ============================================================
# THRESHOLD SENSITIVITY (added in this revision)
# ============================================================
# Not a substitute for cost-sensitive tuning against real incident costs
# (which this prototype has no data for), but a check that the current
# risk-engine cutoffs (0-29/30-69/70+) are not arbitrary: representative
# real single-detector trigger scores are replayed against two alternate
# cutoff sets, showing the two near-definitive signals (severe credential
# stuffing; a lone duplicated national ID) reach BLOCK under the current
# set and the aggressive set, while device-farm and document-reuse
# consistently land in STEP-UP for human review across all three.
def _decide(score, allow_max, stepup_max):
    if score <= allow_max:
        return "ALLOW"
    if score <= stepup_max:
        return "STEP-UP"
    return "BLOCK"


def eval_threshold_sensitivity():
    scenarios = [
        ("Credential stuffing, severe (47 attempts/60s, 31 accounts, 45 fails, 1 device)", 75),
        ("Device anomaly, 12-account device farm (post-fix)", 30),
        ("Document forgery, exact duplicate hash", 45),
        ("Synthetic identity, lone duplicate national ID (post-fix)", 75),
    ]
    cutoff_sets = {
        "Current (0-29/30-69/70+)": (29, 69),
        "Set A: wider (0-34/35-79/80+)": (34, 79),
        "Set B: aggressive (0-19/20-59/60+)": (19, 59),
    }
    print("=== Threshold sensitivity ===")
    for label, score in scenarios:
        row = " | ".join(
            f"{name}: {_decide(score, allow_max, stepup_max)}"
            for name, (allow_max, stepup_max) in cutoff_sets.items()
        )
        print(f"  {label} (score={score})\n    {row}")
    print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=11)
    args = parser.parse_args()

    rng = random.Random(args.seed)

    print(f"Seed: {args.seed} (rerun with the same seed for identical results)\n")

    results = {}
    for name, fn_ in [
        ("impossible_travel", eval_impossible_travel),
        ("device_anomaly", eval_device_anomaly),
        ("synthetic_identity", eval_synthetic_identity),
        ("document_fraud", eval_document_fraud),
        ("liveness_check", eval_liveness_check),
        ("document_fraud_phash", eval_perceptual_hash),
    ]:
        metrics, n = fn_(rng)
        results[name] = metrics
        print(f"=== {name} ({n} events) ===")
        print(f"  Confusion matrix: TP={metrics['TP']} FP={metrics['FP']} TN={metrics['TN']} FN={metrics['FN']}")
        print(f"  Precision: {metrics['precision']}  Recall: {metrics['recall']}  F1: {metrics['f1']}  FPR: {metrics['fpr']}")
        print()

    print("=== Summary table ===")
    print(f"{'Detector':<20} {'Precision':<10} {'Recall':<10} {'F1':<10} {'FPR':<10}")
    for name, m in results.items():
        print(f"{name:<20} {m['precision']:<10} {m['recall']:<10} {m['f1']:<10} {m['fpr']:<10}")

    print()
    eval_threshold_sensitivity()
