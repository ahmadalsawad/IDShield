"""
detectors package

Every detector module exposes:

    DETECTOR_NAME: str
    DETECTOR_VERSION: str
    run(db, auth_event) -> dict

The returned dict always has this shape, so risk_engine.py can combine
detectors it knows nothing else about:

    {
        "detector": "credential_stuffing",
        "detector_version": "0.1.0",
        "triggered": bool,
        "score": float,          # this detector's contribution, 0-100
        "confidence": float,     # 0.0-1.0
        "evidence": [
            {"label": str, "value": ..., "contribution": float}, ...
        ],
    }

Keeping this contract identical across detectors is what lets the SOC
dashboard render "Explain this decision" generically instead of having
special-case UI per detector.
"""
