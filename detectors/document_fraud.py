"""
detectors/document_fraud.py

WHAT THIS DETECTS — and, just as importantly, what it does NOT claim to
detect. Per the project brief, this module must distinguish between
"TAMPERING INDICATORS DETECTED" and "PROVEN FORGERY" — it only ever
produces the former. Real forensic image-tampering detection (error-level
analysis, compression-artifact forensics, etc.) is a research problem in
its own right; attempting it shallowly would manufacture false confidence,
which is worse than not claiming it at all. Everything here is a
verifiable, explainable check:

1. DUPLICATE DOCUMENT HASH — the exact same file (byte-for-byte, via
   SHA-256) was previously uploaded under a DIFFERENT identity. There is
   no legitimate reason two different citizens submit the identical
   document file; this is the strongest signal this detector can produce.

2. REGISTRY MISMATCH — the name or document number written ON the
   submitted document (declared at upload time) does not match what that
   username registered with. A real, unaltered document should agree with
   the registry it's supposedly proving.

3. FILE INTEGRITY ANOMALY — the upload isn't a valid, readable image at
   all, or has an implausible size (near-zero or absurdly large for a
   scanned ID). This catches corrupted/placeholder files, not forgery
   specifically, but it's a legitimate data-quality signal worth
   surfacing.

We do NOT attempt pixel-level tamper detection, portrait-swap detection,
or font/layout analysis — those would require a real forensic pipeline
and dataset this prototype does not have, and claiming otherwise would be
exactly the kind of unsupported claim the brief warns against.

4. EXIF METADATA CHECK — a real, if modest, metadata-forensics signal:
   if the file's EXIF data names known image-editing software (Photoshop,
   GIMP, Snapseed, Lightroom, Canva, Paint.NET, Affinity Photo, etc.) in
   its "Software" tag, that is itself verifiable evidence the file was
   processed by an editor at some point — not proof of fraud (many
   legitimate scans pass through editing software for cropping/rotation),
   but a genuine, disclosed indicator distinct from the hash/registry
   checks above. This is the "metadata check" layer named in the original
   brief, scoped honestly: we read a real EXIF field and match it against
   a known list, we do not infer anything about pixel content.
"""

DETECTOR_NAME = "document_fraud"
DETECTOR_VERSION = "0.3.0"

POINTS_DUPLICATE_HASH = 45
POINTS_NAME_MISMATCH = 25
POINTS_DOCUMENT_NUMBER_MISMATCH = 30
POINTS_FILE_INTEGRITY = 15
POINTS_EDITING_SOFTWARE_METADATA = 15
POINTS_PERCEPTUAL_NEAR_DUPLICATE = 35

PERCEPTUAL_HAMMING_THRESHOLD = 8  # out of 64 bits; distance this low means visually near-identical

TRIGGER_THRESHOLD = 20

MIN_PLAUSIBLE_BYTES = 2 * 1024        # 2 KB — anything smaller is very unlikely to be a real scanned document
MAX_PLAUSIBLE_BYTES = 15 * 1024 * 1024  # 15 MB — generous upper bound for a mock document image

# Known image-editing software signatures that sometimes appear in the
# EXIF "Software" tag. Matching is substring-based and case-insensitive.
# This is a real, verifiable metadata field — not an inference about the
# image's actual pixel content.
EDITING_SOFTWARE_SIGNATURES = [
    "photoshop", "gimp", "snapseed", "lightroom", "canva", "paint.net",
    "affinity photo", "pixelmator", "illustrator", "picsart", "fotor",
]


def _normalize(s):
    return (s or "").strip().lower()


def _matches_editing_software(exif_software: str | None) -> bool:
    if not exif_software:
        return False
    lowered = exif_software.lower()
    return any(sig in lowered for sig in EDITING_SOFTWARE_SIGNATURES)


def _hamming_distance(hash1: str | None, hash2: str | None) -> int:
    """Bit-distance between two hex-encoded perceptual hashes. Returns 64
    (maximally different) if either hash is missing or unparseable, so a
    missing hash never accidentally counts as a match."""
    if not hash1 or not hash2:
        return 64
    try:
        return bin(int(hash1, 16) ^ int(hash2, 16)).count("1")
    except ValueError:
        return 64


def analyze(candidate: dict, prior_uploads: list[dict], registry_record: dict | None) -> dict:
    """
    candidate: dict with keys:
        file_hash (str), file_size_bytes (int), is_valid_image (bool),
        declared_full_name (str|None), declared_document_number (str|None),
        username (str), exif_software (str|None, optional), perceptual_hash
        (str|None, optional) — a 64-bit average-hash fingerprint of the
        image's visual content (see app.py's _compute_perceptual_hash),
        None if the file couldn't be read as an image.
    prior_uploads: list of dicts, each with keys: file_hash, username,
        perceptual_hash (optional) — every OTHER previously uploaded
        document, any user.
    registry_record: dict with keys full_name, document_number for the
        username on this candidate, or None if that username isn't
        registered / hasn't supplied those fields.

    Returns the standard detector result dict.
    """
    evidence = []
    total_score = 0.0

    duplicate_matches = [
        u for u in prior_uploads
        if u["file_hash"] == candidate["file_hash"] and u["username"] != candidate["username"]
    ]
    if duplicate_matches:
        other_usernames = sorted({u["username"] for u in duplicate_matches})
        evidence.append({
            "label": (
                f"TAMPERING INDICATOR: identical document file previously "
                f"submitted under different account(s): {other_usernames}"
            ),
            "value": candidate["file_hash"],
            "contribution": POINTS_DUPLICATE_HASH,
        })
        total_score += POINTS_DUPLICATE_HASH
    elif candidate.get("perceptual_hash"):
        # Only checked when the exact hash DIDN'T already match — this is
        # specifically for the case a same-hash check cannot catch: the
        # same underlying image, re-saved/re-compressed/resized so its raw
        # bytes (and therefore SHA-256) differ completely, but it still
        # looks the same. A well-established computer-vision technique
        # (average hashing), not a forensic tampering claim.
        near_dupes = [
            (u["username"], _hamming_distance(candidate["perceptual_hash"], u.get("perceptual_hash")))
            for u in prior_uploads
            if u["username"] != candidate["username"]
        ]
        near_dupes = [(uname, dist) for uname, dist in near_dupes if dist <= PERCEPTUAL_HAMMING_THRESHOLD]
        if near_dupes:
            best_username, best_dist = min(near_dupes, key=lambda x: x[1])
            evidence.append({
                "label": (
                    f"TAMPERING INDICATOR: visually near-identical document "
                    f"(perceptual hash distance {best_dist}/64 bits) previously "
                    f"submitted under a different account ('{best_username}') — "
                    f"consistent with the same file re-saved or re-compressed, "
                    f"not a byte-for-byte copy"
                ),
                "value": {"username": best_username, "hamming_distance": best_dist},
                "contribution": POINTS_PERCEPTUAL_NEAR_DUPLICATE,
            })
            total_score += POINTS_PERCEPTUAL_NEAR_DUPLICATE

    if registry_record:
        if candidate.get("declared_full_name") and registry_record.get("full_name"):
            if _normalize(candidate["declared_full_name"]) != _normalize(registry_record["full_name"]):
                evidence.append({
                    "label": (
                        f"TAMPERING INDICATOR: name on document "
                        f"('{candidate['declared_full_name']}') does not match "
                        f"registered identity ('{registry_record['full_name']}')"
                    ),
                    "value": candidate["declared_full_name"],
                    "contribution": POINTS_NAME_MISMATCH,
                })
                total_score += POINTS_NAME_MISMATCH

        if candidate.get("declared_document_number") and registry_record.get("document_number"):
            if _normalize(candidate["declared_document_number"]) != _normalize(registry_record["document_number"]):
                evidence.append({
                    "label": (
                        f"TAMPERING INDICATOR: document number on file "
                        f"('{candidate['declared_document_number']}') does not match "
                        f"registered document number ('{registry_record['document_number']}')"
                    ),
                    "value": candidate["declared_document_number"],
                    "contribution": POINTS_DOCUMENT_NUMBER_MISMATCH,
                })
                total_score += POINTS_DOCUMENT_NUMBER_MISMATCH

    size = candidate.get("file_size_bytes", 0)
    implausible_size = size < MIN_PLAUSIBLE_BYTES or size > MAX_PLAUSIBLE_BYTES
    not_a_valid_image = not candidate.get("is_valid_image", False)
    if implausible_size or not_a_valid_image:
        reasons = []
        if not_a_valid_image:
            reasons.append("file is not a readable image")
        if implausible_size:
            reasons.append(f"implausible file size ({size} bytes)")
        evidence.append({
            "label": f"File integrity anomaly: {', '.join(reasons)}",
            "value": {"size_bytes": size, "is_valid_image": candidate.get("is_valid_image", False)},
            "contribution": POINTS_FILE_INTEGRITY,
        })
        total_score += POINTS_FILE_INTEGRITY

    exif_software = candidate.get("exif_software")
    if _matches_editing_software(exif_software):
        evidence.append({
            "label": (
                f"METADATA INDICATOR: file's EXIF data names image-editing "
                f"software ('{exif_software}') — not proof of tampering, but "
                f"a real, disclosed metadata signal worth a closer look"
            ),
            "value": exif_software,
            "contribution": POINTS_EDITING_SOFTWARE_METADATA,
        })
        total_score += POINTS_EDITING_SOFTWARE_METADATA

    total_score = min(total_score, 100.0)
    confidence = 0.95 if duplicate_matches else (0.7 if evidence else 0.3)

    return {
        "detector": DETECTOR_NAME,
        "detector_version": DETECTOR_VERSION,
        "triggered": total_score >= TRIGGER_THRESHOLD,
        "score": total_score,
        "confidence": confidence,
        "evidence": evidence,
        # Explicit, jury-facing classification distinct from "proven forgery" —
        # see module docstring. Never upgrade this string to a stronger claim.
        "classification": "TAMPERING_INDICATORS_DETECTED" if total_score >= TRIGGER_THRESHOLD else "NO_INDICATORS_DETECTED",
    }


def run(db, document_upload) -> dict:
    from models import DocumentUpload, User

    prior_rows = (
        db.query(DocumentUpload)
        .filter(DocumentUpload.id != document_upload.id)
        .all()
    )
    prior_uploads = [
        {"file_hash": r.file_hash_sha256, "username": r.username_submitted, "perceptual_hash": r.perceptual_hash}
        for r in prior_rows
    ]

    registry_record = None
    if document_upload.user_id is not None:
        user = db.query(User).filter(User.id == document_upload.user_id).first()
        if user:
            registry_record = {"full_name": user.full_name, "document_number": user.document_number}

    perceptual_hash = getattr(document_upload, "_perceptual_hash", None)
    document_upload.perceptual_hash = perceptual_hash  # persist for future comparisons

    candidate = {
        "file_hash": document_upload.file_hash_sha256,
        "file_size_bytes": document_upload.file_size_bytes,
        "is_valid_image": getattr(document_upload, "_is_valid_image", True),
        "declared_full_name": document_upload.declared_full_name,
        "declared_document_number": document_upload.declared_document_number,
        "username": document_upload.username_submitted,
        "exif_software": getattr(document_upload, "_exif_software", None),
        "perceptual_hash": perceptual_hash,
    }

    return analyze(candidate, prior_uploads, registry_record)


if __name__ == "__main__":
    import json

    prior = [{"file_hash": "abc123", "username": "real_citizen"}]
    registry = {"full_name": "Fatima Al Suwaidi", "document_number": "IDN-88213940"}

    # Reused document file under a different account + mismatched name.
    fraud_candidate = {
        "file_hash": "abc123",
        "file_size_bytes": 500_000,
        "is_valid_image": True,
        "declared_full_name": "Someone Else",
        "declared_document_number": "IDN-88213940",
        "username": "synthetic_fake",
    }
    result = analyze(fraud_candidate, prior, registry)
    print("Reused document + name mismatch:")
    print(json.dumps(result, indent=2))
    assert result["triggered"] is True
    assert result["classification"] == "TAMPERING_INDICATORS_DETECTED"

    # Clean upload: new hash, matches registry, valid image, normal size.
    clean_candidate = {
        "file_hash": "def456",
        "file_size_bytes": 500_000,
        "is_valid_image": True,
        "declared_full_name": "Fatima Al Suwaidi",
        "declared_document_number": "IDN-88213940",
        "username": "real_citizen",
    }
    clean_result = analyze(clean_candidate, prior, registry)
    print("\nClean upload:")
    print(json.dumps(clean_result, indent=2))
    assert clean_result["triggered"] is False
    assert clean_result["classification"] == "NO_INDICATORS_DETECTED"

    # New: EXIF metadata signal alone — clean hash/registry, but the file
    # was processed through Photoshop per its own metadata.
    edited_candidate = {
        "file_hash": "ghi789",
        "file_size_bytes": 500_000,
        "is_valid_image": True,
        "declared_full_name": "Fatima Al Suwaidi",
        "declared_document_number": "IDN-88213940",
        "username": "real_citizen",
        "exif_software": "Adobe Photoshop 25.0",
    }
    edited_result = analyze(edited_candidate, prior, registry)
    print("\nEdited-metadata-only upload:")
    print(json.dumps(edited_result, indent=2))
    assert edited_result["triggered"] is False  # weak signal alone (15 pts) stays below the 20-point threshold, by design
    assert any("METADATA INDICATOR" in e["label"] for e in edited_result["evidence"])

    # New: perceptual hash — the actual case SHA-256 alone cannot catch.
    # Generate a real image, hash it, re-save it at a different JPEG
    # quality (changing every byte and therefore the SHA-256), and verify
    # the perceptual hash still recognizes it as the same image.
    import io as _io
    from PIL import Image as _Image

    def _fake_document_bytes(quality):
        img = _Image.new("RGB", (400, 300), color=(120, 140, 160))
        # A few shapes so the image isn't a flat, trivially-hashable block.
        for x in range(0, 400, 40):
            for y in range(0, 300, 40):
                if (x + y) % 80 == 0:
                    img.putpixel((x, y), (200, 50, 50))
        buf = _io.BytesIO()
        img.save(buf, format="JPEG", quality=quality)
        return buf.getvalue()

    def _ahash(raw_bytes):
        img = _Image.open(_io.BytesIO(raw_bytes)).convert("L").resize((8, 8), _Image.LANCZOS)
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p >= avg else "0" for p in pixels)
        return f"{int(bits, 2):016x}"

    original_bytes = _fake_document_bytes(quality=95)
    recompressed_bytes = _fake_document_bytes(quality=40)  # same image, heavily re-compressed

    original_sha256 = hashlib_sha256 = __import__("hashlib").sha256(original_bytes).hexdigest()
    recompressed_sha256 = __import__("hashlib").sha256(recompressed_bytes).hexdigest()
    assert original_sha256 != recompressed_sha256, "Test setup check: re-compression should change SHA-256"

    original_phash = _ahash(original_bytes)
    recompressed_phash = _ahash(recompressed_bytes)
    dist = _hamming_distance(original_phash, recompressed_phash)
    print(f"\nPerceptual hash test: SHA-256 differs (as expected), Hamming distance = {dist}/64")

    prior_with_phash = [{"file_hash": original_sha256, "username": "real_owner", "perceptual_hash": original_phash}]
    reencoded_candidate = {
        "file_hash": recompressed_sha256,  # DIFFERENT from original — SHA-256 alone would miss this
        "file_size_bytes": len(recompressed_bytes),
        "is_valid_image": True,
        "declared_full_name": "Different Person",
        "declared_document_number": "IDN-99999999",
        "username": "thief_account",
        "perceptual_hash": recompressed_phash,
    }
    phash_result = analyze(reencoded_candidate, prior_with_phash, None)
    print(json.dumps(phash_result, indent=2))
    assert dist <= PERCEPTUAL_HAMMING_THRESHOLD, f"Expected near-identical hash, got distance {dist}"
    assert phash_result["triggered"] is True
    assert any("visually near-identical" in e["label"] for e in phash_result["evidence"])

    print("\nAll self-tests passed.")
