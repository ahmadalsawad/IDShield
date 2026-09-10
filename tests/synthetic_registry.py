"""
tests/synthetic_registry.py

Generates a synthetic citizen registry, structured like a real government
digital-identity record (national ID format, address, document fields).
ALL DATA IS FICTIONAL — names, IDs, phone numbers, addresses, devices, and
IPs are generated, never real. Formats borrow from real-world conventions
(e.g. a UAE-style national ID pattern) purely for realism in the demo.

Usage:
    python tests/synthetic_registry.py --count 50

Writes: data/synthetic_citizens.json

This registry is the single source of truth other scripts draw from:
- tests/traffic_generator.py uses it to fire real login attempts
- Phase 4 (synthetic identity) will reuse it to plant deliberate
  duplicate phones/devices/addresses for that detector to catch
- Phase 8 (evaluation) will reuse it to build the labeled dataset

Nothing here talks to the API — it only produces the JSON file. Separating
"who exists" (this file) from "what they do" (traffic_generator.py) keeps
the two concerns testable independently.
"""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

FEMALE_FIRST_NAMES = [
    "Fatima", "Layla", "Mariam", "Aisha", "Noura", "Sara", "Huda", "Salma",
    "Amina", "Reem", "Hessa", "Shamma", "Alia", "Maitha", "Wadha",
]
MALE_FIRST_NAMES = [
    "Ahmed", "Omar", "Khalid", "Youssef", "Hassan", "Rashid", "Tariq", "Zayd",
    "Faisal", "Waleed", "Sultan", "Majid", "Saeed", "Hamdan", "Marwan",
]
LAST_NAMES = [
    "Al Suwaidi", "Al Mansoori", "Al Falasi", "Al Marri", "Al Zaabi",
    "Al Shamsi", "Al Nuaimi", "Al Kaabi", "Al Hashimi", "Al Qassimi",
]
CITIES = ["Dubai", "Abu Dhabi", "Sharjah", "Ajman", "Ras Al Khaimah", "Fujairah"]
STREETS = ["Al Wasl Road", "Sheikh Zayed Road", "Corniche Street", "King Faisal Street", "Al Ittihad Road"]
DOCUMENT_TYPES = ["National ID", "Passport"]


def _random_national_id(rng: random.Random) -> str:
    year = rng.randint(1975, 2005)
    serial = rng.randint(1_000_000, 9_999_999)
    check = rng.randint(0, 9)
    return f"784-{year}-{serial}-{check}"


def _random_phone(rng: random.Random) -> str:
    prefix = rng.choice(["50", "52", "54", "55", "56", "58"])
    number = rng.randint(1_000_000, 9_999_999)
    return f"+971-{prefix}-{number}"


def _random_device_id(rng: random.Random) -> str:
    return f"device-{rng.getrandbits(32):08x}"


def _random_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def generate_citizen(rng: random.Random, index: int) -> dict:
    gender = rng.choice(["M", "F"])
    first = rng.choice(MALE_FIRST_NAMES if gender == "M" else FEMALE_FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    full_name = f"{first} {last}"
    username = f"{first.lower()}.{last.lower().replace(' ', '')}{index}"

    dob_year = rng.randint(1965, 2005)
    dob = datetime(dob_year, rng.randint(1, 12), rng.randint(1, 28))

    issue = datetime(rng.randint(2018, 2023), rng.randint(1, 12), rng.randint(1, 28))
    expiry = issue.replace(year=issue.year + 10)

    reg_time = datetime.now(timezone.utc) - timedelta(days=rng.randint(1, 900))

    return {
        "national_id": _random_national_id(rng),
        "full_name": full_name,
        "date_of_birth": dob.strftime("%Y-%m-%d"),
        "gender": gender,
        "nationality": "UAE",
        "phone_number": _random_phone(rng),
        "email": f"{username}{rng.randint(100,999)}@example-mail.test",
        "address": {
            "emirate": rng.choice(CITIES),
            "street": rng.choice(STREETS),
            "building": f"Building {rng.randint(1,60)}, Apt {rng.randint(100,499)}",
        },
        "document_type": rng.choice(DOCUMENT_TYPES),
        "document_number": f"IDN-{rng.randint(10_000_000, 99_999_999)}",
        "document_issue_date": issue.strftime("%Y-%m-%d"),
        "document_expiry_date": expiry.strftime("%Y-%m-%d"),
        "registered_device_id": _random_device_id(rng),
        "registered_ip": _random_ip(rng),
        "account_username": username,
        # Plaintext password ONLY here, in the generator's own output file —
        # it's needed so traffic_generator.py can call the real /register
        # and /login endpoints. The server itself never stores this value;
        # it stores security.hash_password()'s output instead.
        "account_password": f"Synth-{rng.randint(100000,999999)}!",
        "registration_timestamp": reg_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic citizen registry")
    parser.add_argument("--count", type=int, default=50, help="Number of synthetic citizens")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    parser.add_argument("--out", type=str, default="data/synthetic_citizens.json")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    citizens = [generate_citizen(rng, i) for i in range(args.count)]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(citizens, indent=2))

    print(f"Generated {len(citizens)} synthetic citizens -> {out_path}")
    print(f"Seed: {args.seed} (rerun with the same seed for identical data)")


if __name__ == "__main__":
    main()
