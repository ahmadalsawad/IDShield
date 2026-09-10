"""
tests/generate_labeled_dataset.py

Builds a LARGE, labeled login-event dataset from the citizen registry:
- Legitimate sessions: each citizen logging in correctly, from their own
  device/IP, spread across time (this is realistic background traffic —
  the vast majority of any real system's volume, and the thing a good
  detector must NOT flag).
- Credential-stuffing campaigns: bursts of attempts against many
  citizens' usernames, from a small number of attacker devices/IPs,
  concentrated in short time windows, mostly wrong passwords.

Every single event gets a ground_truth_label ("legitimate" or
"credential_stuffing"). This is what makes it possible to compute real
precision/recall/F1 later — we always know what SHOULD have happened,
independent of what the detector says.

This does NOT call the detector or the API. It only produces the data.
See tests/evaluate_credential_stuffing.py for what consumes it.

Usage:
    python tests/generate_labeled_dataset.py \\
        --citizens data/synthetic_citizens.json \\
        --sessions-per-citizen 2 \\
        --attack-campaigns 30 \\
        --seed 7
"""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

LEGITIMATE = "legitimate"
CREDENTIAL_STUFFING = "credential_stuffing"


def generate_legitimate_events(citizens, rng, sessions_per_citizen, start_time):
    """Each citizen logs in correctly, from their own registered device/IP,
    at a random point across a ~30 day window. This is normal background noise."""
    events = []
    for citizen in citizens:
        for _ in range(sessions_per_citizen):
            ts = start_time + timedelta(
                days=rng.uniform(0, 30),
                hours=rng.uniform(0, 24),
            )
            events.append({
                "username_attempted": citizen["account_username"],
                "password_used": citizen["account_password"],  # correct password
                "success": True,
                "source_ip": citizen["registered_ip"],
                "device_id": citizen["registered_device_id"],
                "timestamp": ts.isoformat(),
                "ground_truth_label": LEGITIMATE,
                "campaign_id": None,
            })
    return events


def generate_credential_stuffing_campaigns(citizens, rng, num_campaigns, start_time):
    """Each campaign = one attacker, 1-2 devices/IPs, targeting a random
    batch of real usernames with wrong passwords, compressed into a short
    burst. A small success rate models the real-world case where some
    leaked passwords in the attacker's list happen to be correct."""
    events = []
    for campaign_index in range(num_campaigns):
        campaign_id = f"stuffing-{campaign_index:03d}"
        burst_size = rng.randint(20, 80)
        targets = rng.sample(citizens, k=min(burst_size, len(citizens)))

        attacker_ips = [f"198.51.100.{rng.randint(1,254)}" for _ in range(rng.randint(1, 2))]
        attacker_devices = [f"device-attacker-{rng.getrandbits(24):06x}" for _ in range(rng.randint(1, 2))]

        campaign_start = start_time + timedelta(days=rng.uniform(0, 30), hours=rng.uniform(0, 24))
        window_seconds = rng.randint(20, 55)  # compressed burst, well under the 60s detector window

        for i, citizen in enumerate(targets):
            ts = campaign_start + timedelta(seconds=rng.uniform(0, window_seconds))
            success = rng.random() < 0.04  # ~4% of guesses happen to be correct
            events.append({
                "username_attempted": citizen["account_username"],
                "password_used": citizen["account_password"] if success else "wrong-guess-123",
                "success": success,
                "source_ip": rng.choice(attacker_ips),
                "device_id": rng.choice(attacker_devices),
                "timestamp": ts.isoformat(),
                "ground_truth_label": CREDENTIAL_STUFFING,
                "campaign_id": campaign_id,
            })
    return events


def main():
    parser = argparse.ArgumentParser(description="Generate a large labeled login-event dataset")
    parser.add_argument("--citizens", type=str, default="data/synthetic_citizens.json")
    parser.add_argument("--sessions-per-citizen", type=int, default=2)
    parser.add_argument("--attack-campaigns", type=int, default=30)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=str, default="data/labeled_events.json")
    args = parser.parse_args()

    citizens = json.loads(Path(args.citizens).read_text())
    rng = random.Random(args.seed)
    start_time = datetime.now(timezone.utc) - timedelta(days=30)

    legit = generate_legitimate_events(citizens, rng, args.sessions_per_citizen, start_time)
    attacks = generate_credential_stuffing_campaigns(citizens, rng, args.attack_campaigns, start_time)

    all_events = legit + attacks
    rng.shuffle(all_events)  # interleave, since real traffic isn't neatly sorted by type
    all_events.sort(key=lambda e: e["timestamp"])  # then order chronologically, like a real log

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(all_events, indent=2))

    print(f"Legitimate events:        {len(legit)}")
    print(f"Credential-stuffing events: {len(attacks)}  ({args.attack_campaigns} campaigns)")
    print(f"Total events:              {len(all_events)}")
    print(f"Written to: {out_path}")
    print(f"Seed: {args.seed} (rerun with the same seed for identical data)")


if __name__ == "__main__":
    main()
