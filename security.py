"""
security.py

Password hashing using PBKDF2-HMAC-SHA256 from Python's stdlib `hashlib`.

WHY NOT bcrypt/passlib:
Either would be fine and arguably nicer, but PBKDF2 via hashlib needs
zero extra dependencies, which matters in an offline/competition
environment where you might not have reliable pip access on demo day.
It's still a real, salted, iterated hash — not the "plaintext password
storage" anti-pattern you specifically asked me to flag and avoid.

Format stored in User.password_hash: "pbkdf2$<iterations>$<salt_hex>$<hash_hex>"
Storing the iteration count and salt alongside the hash means we can
raise the iteration count later without invalidating old hashes.
"""

import hashlib
import hmac
import secrets

ITERATIONS = 260_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"pbkdf2${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations_str, salt_hex, digest_hex = stored_hash.split("$")
    except ValueError:
        return False
    if scheme != "pbkdf2":
        return False
    iterations = int(iterations_str)
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(digest_hex)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


if __name__ == "__main__":
    h = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", h) is True
    assert verify_password("wrong-password", h) is False
    print("Self-test passed:", h[:40], "...")
