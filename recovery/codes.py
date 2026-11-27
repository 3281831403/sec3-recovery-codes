"""Recovery code generation, storage, and redemption helpers.

Security contract:

* A batch is generated all at once; codes within a batch are pairwise
  distinct and obey the policy length/alphabet.
* Only salted hashes of codes are ever persisted; plaintext codes are not
  kept on a batch.
* Each code can succeed at most once.  A successful redemption marks the
  entry used and removes it from the available set, so the number of
  available codes only ever decreases.
* Different batches draw from independent streams.
"""

from __future__ import annotations

import hashlib
import hmac
import json


class _Stream:
    """Deterministic byte stream used where a seeded generator is needed."""

    def __init__(self, seed):
        self._seed = str(seed).encode("utf-8")
        self._counter = 0
        self._buf = b""

    def bytes(self, n):
        out = b""
        while len(out) < n:
            if not self._buf:
                self._buf = hashlib.sha256(
                    self._seed + b":" + str(self._counter).encode()
                ).digest()
                self._counter += 1
            piece = self._buf[: n - len(out)]
            out += piece
            self._buf = self._buf[len(piece):]
        return out

    def randbelow(self, n):
        """Uniform integer in [0, n) via rejection sampling (no modulo bias)."""
        if n <= 0:
            raise ValueError("randbelow() requires a positive bound")
        size = (n - 1).bit_length()
        modulus = 1 << size
        limit = modulus - (modulus % n)
        while True:
            candidate = int.from_bytes(self.bytes((size + 7) // 8), "big")
            candidate %= modulus
            if candidate < limit:
                return candidate % n


def generate(entropy, policy):
    """Generate one batch of pairwise-distinct recovery codes.

    The whole batch draws from a single stream, so codes within the batch
    differ; every call builds a fresh stream from ``entropy``, keeping
    batches independent of one another.
    """
    count = int(policy["count"])
    length = int(policy["length"])
    alphabet = str(policy["alphabet"])
    if count < 0:
        raise ValueError("count must be non-negative")
    if length <= 0:
        raise ValueError("length must be positive")
    if not alphabet:
        raise ValueError("alphabet must not be empty")
    # The policy space must be large enough to hold a unique code per slot.
    space = len(alphabet) ** length
    if count > space:
        raise ValueError("policy cannot provide enough distinct codes")

    rng = _Stream(entropy)
    codes = []
    seen = set()
    # Rejection sampling guarantees pairwise distinct codes.  The cap only
    # guards against pathologically small alphabets/lengths.
    max_attempts = count * 100 + 1000
    attempts = 0
    while len(codes) < count:
        attempts += 1
        if attempts > max_attempts:
            raise RuntimeError("failed to generate distinct codes")
        code = "".join(alphabet[rng.randbelow(len(alphabet))] for _ in range(length))
        if code in seen:
            continue
        seen.add(code)
        codes.append(code)
    return codes


def hash_code(code, salt):
    """Return the salted digest that is persisted for a recovery code."""
    return hmac.new(
        str(salt).encode("utf-8"),
        str(code).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def parse_batch(blob):
    """Turn a persisted batch blob into an in-memory batch.

    Plaintext ``codes`` in the blob are converted to salted hashes; the
    plaintext is never retained.  Blobs that already carry hashed entries
    are accepted as-is.
    """
    data = json.loads(blob) if isinstance(blob, str) else dict(blob)
    salt = str(data.get("salt", ""))

    if "entries" in data:
        entries = []
        for item in data.get("entries", []):
            entry = dict(item)
            entry.pop("code", None)  # never carry plaintext on a stored entry
            if "hash" not in entry:
                raise ValueError("stored entry is missing its hash")
            entry["used"] = bool(entry.get("used", False))
            entries.append(entry)
        raw_codes = []
    else:
        raw_codes = [str(item) for item in data.get("codes", [])]
        entries = [
            {"hash": hash_code(code, salt), "used": False} for code in raw_codes
        ]

    length = data.get("length")
    if length is None:
        length = len(raw_codes[0]) if raw_codes else 0
    return {"salt": salt, "length": int(length), "entries": entries}


def verify(code, batch, policy):
    """Look up a presented code in the available entries of a batch.

    The full code must match the stored salted hash; fragments cannot
    match.  Used entries are no longer part of the available set and can
    never verify successfully again.
    """
    text = str(code)
    length = int(batch.get("length") or 0)
    if length and len(text) != length:
        return {"ok": False, "index": None, "entry": None}

    digest = hash_code(text, batch.get("salt", ""))
    for index, entry in enumerate(batch.get("entries", [])):
        if entry.get("used"):
            continue
        stored = entry.get("hash")
        if stored and hmac.compare_digest(stored, digest):
            return {"ok": True, "index": index, "entry": entry}
    return {"ok": False, "index": None, "entry": None}


def mark_used(batch, index):
    """Mark the entry at index as used, removing it from the available set."""
    entries = batch.setdefault("entries", [])
    if not isinstance(index, int) or index < 0 or index >= len(entries):
        return {"ok": False, "entry": None}
    entries[index]["used"] = True
    return {"ok": True, "entry": entries[index]}


def remaining(batch):
    """Report how many codes the batch still offers (only ever decreases)."""
    return sum(1 for entry in batch.get("entries", []) if not entry.get("used"))


def validate_batch(batch, policy):
    """Return the problems detected in a stored batch."""
    issues = []
    entries = batch.get("entries", [])
    length = batch.get("length")
    if length is None or int(length) < int(policy["length"]):
        issues.append("length")

    for entry in entries:
        # Plaintext recovery codes must never be persisted.
        if entry.get("code") is not None:
            issues.append("plaintext")
            break

    seen = set()
    for entry in entries:
        fingerprint = entry.get("hash")
        if fingerprint is None:
            fingerprint = entry.get("code")
        if fingerprint is not None:
            if fingerprint in seen:
                issues.append("duplicate")
                break
            seen.add(fingerprint)
    return issues


def recovery_batch(attempts, batch, policy):
    """Check a sequence of attempts against one batch.

    Every attempt is verified independently.  A successful attempt consumes
    its code, so repeating the same code in a later attempt fails: any
    given recovery code can succeed at most once.
    """
    results = []
    for attempt in attempts:
        outcome = verify(attempt, batch, policy)
        if outcome["ok"]:
            mark_used(batch, outcome["index"])
        results.append(
            {
                "ok": outcome["ok"],
                "index": outcome["index"],
                "entry": outcome.get("entry"),
            }
        )
    return {"results": results, "ok": all(item["ok"] for item in results)}
