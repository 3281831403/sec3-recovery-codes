"""Public acceptance tests for the recovery code lifecycle."""

import json

from recovery.codes import (
    generate,
    hash_code,
    mark_used,
    parse_batch,
    recovery_batch,
    remaining,
    verify,
)

POLICY = {
    "count": 5,
    "length": 12,
    "alphabet": "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
}
SALT = "batch-salt-2026"


def _codes():
    return generate(20261119, POLICY)


def _batch(codes=None):
    if codes is None:
        codes = _codes()
    blob = json.dumps({"salt": SALT, "length": POLICY["length"], "codes": codes})
    return parse_batch(blob)


def test_generate_batch_is_unique_and_follows_policy():
    codes = _codes()
    assert len(codes) == POLICY["count"]
    assert len(set(codes)) == POLICY["count"]
    assert all(len(code) == POLICY["length"] for code in codes)
    assert all(set(code) <= set(POLICY["alphabet"]) for code in codes)


def test_codes_are_stored_as_salted_hashes():
    codes = _codes()
    batch = _batch(codes)
    assert len(batch["entries"]) == POLICY["count"]
    for code, entry in zip(codes, batch["entries"]):
        assert "code" not in entry
        assert entry["hash"] == hash_code(code, SALT)
        assert code not in json.dumps(batch)


def test_verify_accepts_exact_code_and_rejects_fragment():
    codes = _codes()
    batch = _batch(codes)
    result = verify(codes[0], batch, POLICY)
    assert result["ok"] is True
    assert result["index"] == 0
    assert verify(codes[0][:4], batch, POLICY)["ok"] is False


def test_used_code_cannot_be_verified_again():
    codes = _codes()
    batch = _batch(codes)
    result = verify(codes[2], batch, POLICY)
    assert result["ok"] is True
    assert mark_used(batch, result["index"])["ok"] is True
    assert verify(codes[2], batch, POLICY)["ok"] is False


def test_two_attempts_are_independent_and_consume_codes():
    codes = _codes()
    batch = _batch(codes)
    outcome = recovery_batch([codes[0], codes[1]], batch, POLICY)
    assert outcome["results"][0]["ok"] is True
    assert outcome["results"][1]["ok"] is True
    assert remaining(batch) == POLICY["count"] - 2