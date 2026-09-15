"""
tests/verify_audit_chain.py

Read-only verifier for the tamper-evident audit chain (see audit_chain.py
and the chain_hash column added to models.py). Walks each of the four
*DetectorResult tables in insertion order and recomputes every row's hash
from GENESIS_HASH forward; reports the first row (if any) where the
stored chain_hash doesn't match what recomputing produces — i.e. the
first place someone edited, deleted, or reordered a past decision's
evidence after it was written.

USAGE:
    python tests/verify_audit_chain.py                  # uses ./idshield.db
    python tests/verify_audit_chain.py --db path/to.db   # explicit path

This never writes to the database — it only SELECTs. Safe to run against
the live production DB at any time, including during a jury demo.
"""

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from audit_chain import verify_chain  # noqa: E402

# (table name, id column is always "id") — the four independent chains.
CHAINED_TABLES = [
    "detector_results",
    "identity_detector_results",
    "document_detector_results",
    "liveness_detector_results",
]

COLUMNS = ["id", "detector_name", "detector_version", "triggered", "score", "confidence", "evidence_json", "chain_hash"]


def verify_table(conn, table_name):
    try:
        cur = conn.execute(f"SELECT {', '.join(COLUMNS)} FROM {table_name} ORDER BY id")
    except sqlite3.OperationalError as e:
        return None, f"skipped ({e})"

    rows = []
    for r in cur.fetchall():
        row = dict(zip(COLUMNS, r))
        row["triggered"] = bool(row["triggered"])
        rows.append(row)

    if not rows:
        return {"valid": True, "checked": 0, "break_at_index": None, "break_at_id": None}, "no rows yet"

    # Rows written before this revision have chain_hash=NULL and aren't
    # part of the chain (see models.py's migration note) — verify only
    # from the first row that actually has a chain_hash onward.
    first_chained = next((i for i, row in enumerate(rows) if row["chain_hash"]), None)
    if first_chained is None:
        return {"valid": True, "checked": 0, "break_at_index": None, "break_at_id": None}, "no chained rows yet (pre-revision data only)"

    result = verify_chain(rows[first_chained:])
    return result, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="idshield.db", help="Path to the SQLite database file")
    args = parser.parse_args()

    if not Path(args.db).exists():
        print(f"Database file not found: {args.db}")
        sys.exit(1)

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)  # read-only connection

    print(f"Verifying audit chains in {args.db}\n")
    overall_valid = True
    for table_name in CHAINED_TABLES:
        result, note = verify_table(conn, table_name)
        if result is None:
            print(f"  {table_name:<28} {note}")
            continue
        status = "VALID" if result["valid"] else "TAMPERED / BROKEN"
        print(f"  {table_name:<28} {status}  (checked {result['checked']} rows)"
              + (f"  <-- break at row id={result['break_at_id']}" if not result["valid"] else "")
              + (f"  [{note}]" if note else ""))
        overall_valid = overall_valid and result["valid"]

    print()
    print("Overall: " + ("all chains intact." if overall_valid else "TAMPERING DETECTED — see above."))
    conn.close()
    sys.exit(0 if overall_valid else 2)


if __name__ == "__main__":
    main()
