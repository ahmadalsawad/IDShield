"""
audit_chain.py

WHAT THIS IS — and, just as importantly, what it is NOT. Per the same
discipline as document_fraud.py's "indicators, not proven forgery," this
module makes a narrow, honest claim: it makes each detector-result table
TAMPER-EVIDENT (any retroactive edit to a row breaks the chain and is
detectable), not tamper-PROOF and not a distributed ledger. This is a
hash chain — the same core primitive blockchain uses for tamper-evidence
— applied to a single-node SQLite table, which is the right scope for a
prototype with one deployment and no need for multi-party consensus.

WHY THIS, WHY NOW: IDShield's central design commitment is auditability
("Explain this decision" for every event). A hash chain closes the one
gap plain evidence_json logging leaves open: nothing currently stops
someone with direct DB access from quietly editing a past decision's
evidence after the fact. Chaining each row to the previous one's hash
means such an edit is immediately detectable by recomputing hashes
forward from any point — without needing a distributed ledger, a
consensus protocol, or gas fees, none of which a single-server
government-portal prototype needs.

RELATIONSHIP TO REAL DEPLOYMENTS (e.g. UAE PASS): UAE PASS's Digital
Vault uses blockchain (historically Hyperledger Fabric/Quorum, with an
Avalanche integration for its 12M+ users announced this month) to make
STORED DOCUMENTS AND SIGNATURES tamper-evident after issuance — a
different problem from IDShield's, which is scoring BEHAVIOR AT THE
MOMENT of a login/registration/upload. This module deliberately does not
try to replicate vault-grade infrastructure; it borrows the one
primitive (hash chaining) that's directly relevant to IDShield's own
audit-trail claim, and stays honest that it is exactly that primitive
and nothing more. A real deployment could periodically anchor this
chain's latest hash to an external ledger for stronger guarantees
without changing anything below.

HOW A CHAIN WORKS HERE: each of the four *DetectorResult tables
(DetectorResult, IdentityDetectorResult, DocumentDetectorResult,
LivenessDetectorResult) is its own independent, append-only chain,
ordered by row id. Row N's chain_hash = SHA-256(row N-1's chain_hash +
canonical JSON of row N's own tamper-relevant fields). The first row in
a table chains from GENESIS_HASH. verify_chain() walks a table in order
and recomputes every hash from scratch; the first row where the
recomputed hash doesn't match what's stored is exactly where tampering
(or corruption) happened.
"""

import hashlib
import json

GENESIS_HASH = "0" * 64

# The exact fields that make a result row what it is. Deliberately
# excludes IDs/timestamps/created_at — those aren't fraud-decision
# content, and including auto-generated surrogate keys would make the
# chain fragile to things that aren't actually tampering. What matters
# is: can the EVIDENCE AND DECISION for this row be edited undetected?
CHAINED_FIELDS = ["detector_name", "detector_version", "triggered", "score", "confidence", "evidence_json"]


def _canonical(record_fields: dict) -> str:
    """Deterministic JSON serialization — same fields always hash the
    same way regardless of dict insertion order, so the chain is
    reproducible by anyone re-verifying it independently."""
    return json.dumps(record_fields, sort_keys=True, separators=(",", ":"), default=str)


def record_fields_for_hash(row: dict) -> dict:
    """Extract exactly the tamper-relevant fields from a row (dict or
    ORM-row-like object with these keys) for hashing."""
    return {field: row[field] for field in CHAINED_FIELDS}


def compute_record_hash(prev_hash: str, row: dict) -> str:
    """The hash that row should carry as its chain_hash, given the
    previous row's chain_hash (or GENESIS_HASH for the first row in a
    table)."""
    payload = (prev_hash or GENESIS_HASH) + "|" + _canonical(record_fields_for_hash(row))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain(rows: list[dict]) -> dict:
    """
    rows: ordered list (by id ascending — the actual insert order) of
        dicts, each with the CHAINED_FIELDS plus a 'chain_hash' key
        holding what was actually stored for that row.

    Returns:
        {"valid": bool, "checked": int, "break_at_index": int|None,
         "break_at_id": Any|None}
    valid=True means every row's stored chain_hash matches what
    recomputing the chain from GENESIS_HASH forward produces — i.e. no
    row's tamper-relevant fields have been altered since it was written,
    and no row has been deleted or reordered (either would also break
    the next row's hash).
    """
    prev = GENESIS_HASH
    for i, row in enumerate(rows):
        expected = compute_record_hash(prev, row)
        if row.get("chain_hash") != expected:
            return {
                "valid": False,
                "checked": i,
                "break_at_index": i,
                "break_at_id": row.get("id"),
            }
        prev = row["chain_hash"]
    return {"valid": True, "checked": len(rows), "break_at_index": None, "break_at_id": None}


if __name__ == "__main__":
    import json as _json

    # --- Self-test 1: a clean, untampered chain verifies OK. ---
    rows = []
    prev = GENESIS_HASH
    for i in range(5):
        fields = {
            "detector_name": "credential_stuffing",
            "detector_version": "0.2.0",
            "triggered": i % 2 == 0,
            "score": 20.0 + i,
            "confidence": 0.7,
            "evidence_json": _json.dumps([{"label": f"evidence #{i}", "contribution": 10}]),
        }
        h = compute_record_hash(prev, fields)
        row = dict(fields, id=i + 1, chain_hash=h)
        rows.append(row)
        prev = h

    result = verify_chain(rows)
    print("Clean chain:", result)
    assert result["valid"] is True

    # --- Self-test 2: tampering with one row's evidence AFTER the fact
    # (e.g. someone editing the DB directly to remove an incriminating
    # evidence line) must be caught, and caught at the RIGHT row. ---
    tampered_rows = [dict(r) for r in rows]
    tampered_rows[2]["evidence_json"] = _json.dumps([{"label": "nothing to see here", "contribution": 0}])
    # Note: chain_hash on row 2 is left as-is (the attacker didn't recompute
    # it — if they did, they'd also need to recompute every row after it,
    # which is the whole point of chaining).
    tampered_result = verify_chain(tampered_rows)
    print("\nTampered chain (row index 2 edited):", tampered_result)
    assert tampered_result["valid"] is False
    assert tampered_result["break_at_index"] == 2

    # --- Self-test 3: a row silently deleted also breaks the chain,
    # since the next row's stored hash no longer matches what
    # recomputing from the (now missing) previous row produces. ---
    deleted_row_chain = [rows[0], rows[1], rows[3], rows[4]]  # row index 2 removed
    deletion_result = verify_chain(deleted_row_chain)
    print("\nChain with row deleted:", deletion_result)
    assert deletion_result["valid"] is False

    print("\nAll self-tests passed.")
