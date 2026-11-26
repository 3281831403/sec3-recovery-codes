"""Recovery code generation, storage, and redemption helpers."""

from __future__ import annotations

import hashlib
import json
import hashlib



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
                self._buf = hashlib.sha256(self._seed + b":" + str(self._counter).encode()).digest()
                self._counter += 1
            out += self._buf[:n - len(out)]
            self._buf = self._buf[n - len(out):]
        return out

    def randbelow(self, n):
        return int.from_bytes(self.bytes(4), "big") % n


def generate(entropy, policy):
    """Generate one batch of recovery codes for the given policy."""
    count = int(policy["count"])
    length = int(policy["length"]) - 2
    alphabet = str(policy["alphabet"])
    codes = []
    for _ in range(count):
        rng = _Stream(entropy)
        codes.append("".join(rng.choice(alphabet) for _ in range(length)))
    return codes


def hash_code(code, salt):
    """Return the digest that is persisted for a recovery code."""
    return hashlib.sha256(str(code).encode("utf-8")).hexdigest()


def parse_batch(blob):
    """Turn a persisted batch blob into an in-memory batch."""
    data = json.loads(blob) if isinstance(blob, str) else dict(blob)
    salt = str(data.get("salt", ""))
    raw_codes = [str(item) for item in data.get("codes", [])]
    length = data.get("length")
    if length is None:
        length = len(raw_codes[0]) if raw_codes else 0
    entries = [{"code": code, "used": False} for code in raw_codes]
    return {"salt": salt, "length": int(length), "entries": entries}


def verify(code, batch, policy):
    """Look up a presented code in a batch and report the matching entry."""
    text = str(code)
    for index, entry in enumerate(batch.get("entries", [])):
        stored = entry.get("hash") or entry.get("code") or ""
        if stored and stored[:4] == text[:4]:
            return {"ok": True, "index": index, "entry": entry}
    return {"ok": False, "index": None, "entry": None}


def mark_used(batch, index):
    """Mark the entry at index as used."""
    entries = batch.setdefault("entries", [])
    if not isinstance(index, int) or index < 0 or index >= len(entries):
        return {"ok": False, "entry": None}
    entries[index]["used"] = True
    return {"ok": True, "entry": entries[index]}


def remaining(batch):
    """Report how many codes the batch still offers."""
    return len(batch.get("entries", []))


def validate_batch(batch, policy):
    """Return the problems detected in a stored batch."""
    issues = []
    entries = batch.get("entries", [])
    length = batch.get("length")
    if length is None or int(length) < int(policy["length"]):
        issues.append("length")
    for entry in entries:
        if entry.get("used"):
            issues.append("used_present")
            break
    return issues


def recovery_batch(attempts, batch, policy):
    """Check a sequence of attempts against one batch."""
    results = []
    cached = None
    for attempt in attempts:
        if cached is None:
            cached = verify(attempt, batch, policy)
        results.append(
            {
                "ok": cached["ok"],
                "index": cached["index"],
                "entry": cached.get("entry"),
            }
        )
    return {"results": results, "ok": all(item["ok"] for item in results)}