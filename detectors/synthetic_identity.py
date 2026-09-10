"""
detectors/synthetic_identity.py

WHAT THIS DETECTS
A newly registered identity that shares attributes with an EXISTING,
supposedly-unrelated identity in the registry — the hallmark of synthetic
identity fraud, where an attacker fabricates a "new" citizen by mixing
real and fake attributes, often reusing a phone number, device, or
document across multiple fabricated identities because generating a
genuinely fresh one for each is harder.

Also checks for logically-impossible attributes on the record in
isolation (no cross-reference needed) — e.g. a document that expires
before it was issued.

WHY THESE SIGNALS, WEIGHTED THIS WAY:
- Duplicate document_number is the strongest signal (a document number
  should be unique to one person, full stop) — no legitimate reason two
  "different" citizens share one.
- Duplicate national_id is equally strong for the same reason.
- Duplicate phone_number and duplicate registered_device_id are strong
  but not absolute (family members might share a phone temporarily;
  shared/public devices exist) — scored high but not maximal.
- Duplicate address is weaker still (multiple real family members
  legitimately live at the same address) — scored lowest of the
  duplicate checks.
- Duplicate registered_ip is the weakest of all (NAT, shared campus/office
  networks, mobile carrier-grade NAT all produce shared IPs innocently) —
  included for completeness but low-weighted.

This mirrors the project brief's instruction to distinguish strong,
near-definitive evidence from weak, corroborating-only evidence, and to
let the jury inspect exactly why an identity was flagged.
"""

from datetime import date

DETECTOR_NAME = "synthetic_identity"
DETECTOR_VERSION = "0.1.0"

POINTS_DUPLICATE_DOCUMENT_NUMBER = 35
POINTS_DUPLICATE_NATIONAL_ID = 35
POINTS_DUPLICATE_PHONE = 25
POINTS_DUPLICATE_DEVICE = 20
POINTS_DUPLICATE_ADDRESS = 12
POINTS_DUPLICATE_IP = 8
POINTS_LOGICAL_INCONSISTENCY = 20

TRIGGER_THRESHOLD = 20


def _find_duplicates(candidate_value, field_name, existing_users):
    if not candidate_value:
        return []
    return [u for u in existing_users if u.get(field_name) == candidate_value]


def analyze(candidate: dict, existing_users: list[dict]) -> dict:
    """
    candidate: dict describing the new registration, with keys matching
        the citizen registry schema (phone_number, national_id,
        document_number, registered_device_id, registered_ip,
        address_street, address_building, document_issue_date,
        document_expiry_date, date_of_birth, ...). Missing/None fields are
        simply skipped by the relevant check.
    existing_users: list of dicts, same schema, for every OTHER user
        already in the registry (candidate excluded).

    Returns the standard detector result dict.
    """
    evidence = []
    total_score = 0.0

    checks = [
        ("document_number", POINTS_DUPLICATE_DOCUMENT_NUMBER, "document number"),
        ("national_id", POINTS_DUPLICATE_NATIONAL_ID, "national ID"),
        ("phone_number", POINTS_DUPLICATE_PHONE, "phone number"),
        ("registered_device_id", POINTS_DUPLICATE_DEVICE, "registration device"),
        ("registered_ip", POINTS_DUPLICATE_IP, "registration IP address"),
    ]
    for field_name, points, label in checks:
        matches = _find_duplicates(candidate.get(field_name), field_name, existing_users)
        if matches:
            other_usernames = [u.get("username") for u in matches]
            evidence.append({
                "label": f"Duplicate {label} shared with existing account(s): {other_usernames}",
                "value": candidate.get(field_name),
                "contribution": points,
            })
            total_score += points

    # Address is two fields together (street + building) — matching on
    # street alone would produce far too many false positives in any
    # real city.
    if candidate.get("address_street") and candidate.get("address_building"):
        address_matches = [
            u for u in existing_users
            if u.get("address_street") == candidate["address_street"]
            and u.get("address_building") == candidate["address_building"]
        ]
        if address_matches:
            other_usernames = [u.get("username") for u in address_matches]
            evidence.append({
                "label": f"Duplicate address shared with existing account(s): {other_usernames}",
                "value": f"{candidate['address_street']}, {candidate['address_building']}",
                "contribution": POINTS_DUPLICATE_ADDRESS,
            })
            total_score += POINTS_DUPLICATE_ADDRESS

    # Logical consistency checks (no cross-reference needed).
    issue = candidate.get("document_issue_date")
    expiry = candidate.get("document_expiry_date")
    if issue and expiry and expiry <= issue:
        evidence.append({
            "label": f"Document expiry date ({expiry}) is not after its issue date ({issue})",
            "value": {"issue": issue, "expiry": expiry},
            "contribution": POINTS_LOGICAL_INCONSISTENCY,
        })
        total_score += POINTS_LOGICAL_INCONSISTENCY

    dob = candidate.get("date_of_birth")
    if dob:
        try:
            birth_year = int(dob[:4])
            age_years = date.today().year - birth_year
            if age_years < 15 or age_years > 110:
                evidence.append({
                    "label": f"Implausible age from date of birth: {age_years} years",
                    "value": age_years,
                    "contribution": POINTS_LOGICAL_INCONSISTENCY,
                })
                total_score += POINTS_LOGICAL_INCONSISTENCY
        except (ValueError, TypeError):
            pass  # malformed date is a data-quality issue, not this detector's job

    total_score = min(total_score, 100.0)
    confidence = 0.9 if any(e["contribution"] >= 30 for e in evidence) else (0.6 if evidence else 0.3)

    return {
        "detector": DETECTOR_NAME,
        "detector_version": DETECTOR_VERSION,
        "triggered": total_score >= TRIGGER_THRESHOLD,
        "score": total_score,
        "confidence": confidence,
        "evidence": evidence,
    }


def run(db, new_user) -> dict:
    from models import User

    existing = db.query(User).filter(User.id != new_user.id).all()

    def _to_dict(u):
        return {
            "username": u.username,
            "phone_number": u.phone_number,
            "national_id": u.national_id,
            "document_number": u.document_number,
            "registered_device_id": u.registered_device_id,
            "registered_ip": u.registered_ip,
            "address_street": u.address_street,
            "address_building": u.address_building,
            "document_issue_date": u.document_issue_date,
            "document_expiry_date": u.document_expiry_date,
            "date_of_birth": u.date_of_birth,
        }

    return analyze(_to_dict(new_user), [_to_dict(u) for u in existing])


if __name__ == "__main__":
    import json

    existing_registry = [
        {"username": "citizen_a", "phone_number": "+971-50-1111111", "national_id": "784-1990-1111111-1",
         "document_number": "IDN-11111111", "registered_device_id": "device-aaa", "registered_ip": "10.0.0.1",
         "address_street": "Al Wasl Road", "address_building": "Building 1, Apt 1",
         "document_issue_date": "2020-01-01", "document_expiry_date": "2030-01-01", "date_of_birth": "1990-01-01"},
    ]

    # Fraudulent candidate: reuses citizen_a's phone AND document number.
    fraud_candidate = {
        "username": "citizen_b_fake", "phone_number": "+971-50-1111111", "national_id": "784-1991-2222222-2",
        "document_number": "IDN-11111111", "registered_device_id": "device-bbb", "registered_ip": "10.0.0.2",
        "address_street": "Sheikh Zayed Road", "address_building": "Building 9, Apt 9",
        "document_issue_date": "2021-01-01", "document_expiry_date": "2031-01-01", "date_of_birth": "1995-01-01",
    }

    result = analyze(fraud_candidate, existing_registry)
    print("Fraudulent candidate (duplicate phone + document):")
    print(json.dumps(result, indent=2))
    assert result["triggered"] is True
    assert result["score"] >= 60

    # Legitimate candidate: no overlap with existing registry.
    clean_candidate = {
        "username": "citizen_c", "phone_number": "+971-50-9999999", "national_id": "784-1992-3333333-3",
        "document_number": "IDN-99999999", "registered_device_id": "device-ccc", "registered_ip": "10.0.0.3",
        "address_street": "Corniche Street", "address_building": "Building 5, Apt 5",
        "document_issue_date": "2022-01-01", "document_expiry_date": "2032-01-01", "date_of_birth": "1992-06-15",
    }
    clean_result = analyze(clean_candidate, existing_registry)
    print("\nLegitimate candidate:")
    print(json.dumps(clean_result, indent=2))
    assert clean_result["triggered"] is False

    print("\nAll self-tests passed.")
