"""
risk_engine.py

Combines the outputs of independent detectors into one final risk score
and decision. This is deliberately dumb: it does NOT re-derive evidence
or second-guess detectors, it just aggregates what they already reported.
That separation is the whole point of the architecture — a detector can
be wrong or missing, but the risk engine's combination logic stays the
same and auditable regardless of how many detectors feed into it.

PROTOTYPE THRESHOLDS (from the project brief):
    0-29   -> ALLOW
    30-69  -> STEP_UP / REVIEW
    70-100 -> BLOCK / INVESTIGATE

These are NOT scientifically validated. They are a defensible starting
point to be tuned later against the Phase 8 labeled synthetic dataset
(precision/recall/F1/FPR). Don't present them to the jury as anything
more than an initial, explainable choice.

COMBINATION STRATEGY (Phase 1):
Simple weighted sum of triggered detectors' scores, capped at 100. This
is intentionally the simplest thing that could work — later phases MAY
introduce correlation bonuses (e.g. two independent detectors agreeing
raises confidence more than either alone), but that's an enhancement to
justify explicitly before adding, not a Phase-1 requirement.
"""

ALLOW_MAX = 29
STEP_UP_MAX = 69
# 70+ => BLOCK

DECISION_ALLOW = "ALLOW"
DECISION_STEP_UP = "STEP_UP"
DECISION_BLOCK = "BLOCK"


def combine(detector_results: list[dict]) -> dict:
    """
    detector_results: list of dicts in the standard detector-result shape
        (see detectors/__init__.py).

    Returns:
        {
            "risk_score": float (0-100),
            "decision": "ALLOW" | "STEP_UP" | "BLOCK",
            "contributing_detectors": [...],   # only those that triggered
            "all_results": [...],              # everything, triggered or not
        }
    """
    triggered = [r for r in detector_results if r["triggered"]]

    raw_total = sum(r["score"] for r in triggered)
    risk_score = min(raw_total, 100.0)

    if risk_score <= ALLOW_MAX:
        decision = DECISION_ALLOW
    elif risk_score <= STEP_UP_MAX:
        decision = DECISION_STEP_UP
    else:
        decision = DECISION_BLOCK

    return {
        "risk_score": round(risk_score, 1),
        "decision": decision,
        "contributing_detectors": triggered,
        "all_results": detector_results,
    }


if __name__ == "__main__":
    # Self-test: one detector triggers with a BLOCK-range score.
    fake_result = {
        "detector": "credential_stuffing",
        "detector_version": "0.1.0",
        "triggered": True,
        "score": 75.0,
        "confidence": 0.97,
        "evidence": [{"label": "example", "value": 1, "contribution": 75.0}],
    }
    outcome = combine([fake_result])
    import json
    print(json.dumps(outcome, indent=2))
    assert outcome["decision"] == DECISION_BLOCK
    print("\nSelf-test passed.")
