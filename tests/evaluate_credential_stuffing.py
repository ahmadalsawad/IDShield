"""
tests/evaluate_credential_stuffing.py

Runs the SAME detectors/credential_stuffing.analyze() function used by the
live app against the full labeled dataset, and computes real precision,
recall, F1, and false-positive rate from that execution. No number in the
output is hand-picked — change the dataset or the detector and these
numbers change with it.

METHODOLOGY:
Events are replayed in chronological order (like a real request stream).
For each event, we rebuild the same "recent window" the live DB query
would produce (same source_ip OR same device_id, within the last 60s)
and ask the detector whether IT sees an attack in progress at that
exact moment. That prediction is compared against the event's
ground_truth_label.

This deliberately does NOT cheat by giving the detector the whole
campaign at once — early events in a real burst may legitimately be
missed until enough volume accumulates (detection latency). Reporting
that honestly, rather than hiding it, is exactly the kind of limitation
the project brief tells us to acknowledge to the jury.

Usage:
    python tests/evaluate_credential_stuffing.py --dataset data/labeled_events.json
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so `detectors` imports work
from detectors import credential_stuffing  # noqa: E402


def load_events(path: str) -> list[dict]:
    raw = json.loads(Path(path).read_text())
    for e in raw:
        e["timestamp"] = datetime.fromisoformat(e["timestamp"])
    return raw


def evaluate(events: list[dict]) -> dict:
    events = sorted(events, key=lambda e: e["timestamp"])

    tp = fp = tn = fn = 0
    per_event_results = []

    for i, current in enumerate(events):
        window_start_bound = current["timestamp"].timestamp() - credential_stuffing.WINDOW_SECONDS
        recent = [
            e for e in events[:i + 1]
            if e["timestamp"].timestamp() >= window_start_bound
            and (e["source_ip"] == current["source_ip"] or e["device_id"] == current["device_id"])
        ]
        detector_input = [
            {
                "username": e["username_attempted"],
                "source_ip": e["source_ip"],
                "device_id": e["device_id"],
                "success": e["success"],
                "timestamp": e["timestamp"],
            }
            for e in recent
        ]

        result = credential_stuffing.analyze(detector_input, now=current["timestamp"])
        predicted_attack = result["triggered"]
        actual_attack = current["ground_truth_label"] == "credential_stuffing"

        if predicted_attack and actual_attack:
            tp += 1
        elif predicted_attack and not actual_attack:
            fp += 1
        elif not predicted_attack and not actual_attack:
            tn += 1
        else:
            fn += 1

        per_event_results.append({
            "campaign_id": current.get("campaign_id"),
            "ground_truth": current["ground_truth_label"],
            "predicted_triggered": predicted_attack,
            "score": result["score"],
        })

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "total_events": len(events),
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "per_event_results": per_event_results,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate credential_stuffing detector against labeled dataset")
    parser.add_argument("--dataset", type=str, default="data/labeled_events.json")
    args = parser.parse_args()

    events = load_events(args.dataset)
    metrics = evaluate(events)

    print(f"Total events evaluated: {metrics['total_events']}")
    print(f"Confusion matrix: {metrics['confusion_matrix']}")
    print(f"Precision:            {metrics['precision']}")
    print(f"Recall:               {metrics['recall']}")
    print(f"F1 score:             {metrics['f1_score']}")
    print(f"False positive rate:  {metrics['false_positive_rate']}")

    # Breakdown by campaign, so we can see WHICH bursts were caught vs missed,
    # not just an aggregate number.
    campaigns = {}
    for r in metrics["per_event_results"]:
        cid = r["campaign_id"]
        if cid is None:
            continue
        campaigns.setdefault(cid, {"total": 0, "caught": 0})
        campaigns[cid]["total"] += 1
        if r["predicted_triggered"]:
            campaigns[cid]["caught"] += 1

    fully_missed = [cid for cid, v in campaigns.items() if v["caught"] == 0]
    print(f"\nCampaigns with at least one detected event: {len(campaigns) - len(fully_missed)}/{len(campaigns)}")
    if fully_missed:
        print(f"Campaigns NEVER detected: {fully_missed}")


if __name__ == "__main__":
    main()
