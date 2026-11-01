"""Shared pieces: the deterministic clock, the canonical encoding, and the signature.

Everything here is fixed. The seed is in the source, the policy digest is a constant, and the
clock is a counter rather than a wall clock, so two runs on two machines produce byte-identical
artifacts. Class V claims only what such a key can support, which is that a binding verifies
against the keys it is given. It is not evidence of production key security or institutional
trust, and the note says so in the same sentence as the claim.
"""

import hashlib
import hmac
import json

# The policy version in force for every run of this benchmark.
POLICY_SHA = "sha256:9f2c0d1b7a44e1d5c3b8a6f0e2d4c1b9a7f5e3d1c9b7a5f3e1d0c8b6a4f2e0d1"
DECIDED_BY = "guard-key-1"

# Fixed seed. Deterministic keys are the point, and the limitation is stated with the claim.
SEED = b"host-failure-benchmark/v1/class-v/fixed-seed"
KEY = hashlib.sha256(SEED).digest()


def canonical(payload):
    """One encoding, so a signature over a record cannot depend on key order."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(payload):
    return hmac.new(KEY, canonical(payload), hashlib.sha256).hexdigest()


def verify(payload, signature):
    if not signature:
        return False
    return hmac.compare_digest(sign(payload), signature)


def frame(record):
    """Per-record frame digest. A torn write stops being a silent truncation."""
    body = {k: v for k, v in record.items() if k != "digest"}
    return hashlib.sha256(canonical(body)).hexdigest()[:32]


def digest(payload):
    return "sha256:" + hashlib.sha256(canonical(payload)).hexdigest()


class Clock:
    """Monotonic, deterministic, phase-labelled. No wall clock anywhere in the artifacts."""

    def __init__(self):
        self.step = 0

    def tick(self, phase):
        self.step += 1
        return {"step": self.step, "phase": phase}


def record_payload(record):
    """The part a signature covers: everything except the signature itself."""
    return {k: v for k, v in record.items() if k != "signature"}


def bound_state(record, action_id):
    """The state of a record, recomputed from its own bytes and the id it is filed under.

    Two things have to be true for a record to count as verified: its signature verifies over
    its own payload, and the id inside the payload is the id it is filed under. Without the
    second, a record signed for one action resolves another one, and no key is needed to do it.

    This is defined once and imported by the store, the verifier and the host, so the three
    cannot drift into disagreeing about what "verified" means. Nothing may read the state off a
    journal field: the journal is a claim, and this is the check.
    """
    if not isinstance(record, dict):
        return "unverified"
    if action_id is not None and record.get("action_id") != action_id:
        return "unbound"
    signature = record.get("signature")
    if not isinstance(signature, str) or not signature:
        return "unverified"
    try:
        return "verified" if verify(record_payload(record), signature) else "unverified"
    except (TypeError, ValueError):
        return "unverified"
