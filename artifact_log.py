# artifact_log.py
"""
Sealed, hash-chained artifact logging for deterministic audit trails.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


@dataclass
class ArtifactRecord:
    ts: float
    profile_id: str
    policy_hash: str
    direction: str
    seq: int
    envelope_hash: str
    chain_hash: str


class ArtifactLogger:
    def __init__(self, log_path: str, log_key: bytes) -> None:
        self.log_path = log_path
        self._log_key = log_key
        self._seq = 0
        self._chain = b"\x00" * 32
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def _nonce(self, seq: int) -> bytes:
        # deterministic nonce derived from log key + seq + chain hash
        return hmac.new(self._log_key, self._chain + seq.to_bytes(8, "big"), hashlib.sha256).digest()[:12]

    def write(self, meta: Dict[str, Any], envelope_bytes: bytes) -> ArtifactRecord:
        self._seq += 1
        env_hash = hashlib.sha256(envelope_bytes).hexdigest()
        chain_prev = self._chain
        record = {
            "ts": time.time(),
            "seq": self._seq,
            "profile_id": meta.get("profile_id"),
            "policy_hash": meta.get("policy_hash"),
            "direction": meta.get("direction"),
            "envelope_hash": env_hash,
            "chain_prev": chain_prev.hex(),
        }
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._chain = hashlib.sha256(chain_prev + encoded).digest()
        record["chain_hash"] = self._chain.hex()

        aead = ChaCha20Poly1305(self._log_key)
        nonce = hmac.new(self._log_key, chain_prev + self._seq.to_bytes(8, "big"), hashlib.sha256).digest()[:12]
        sealed = aead.encrypt(nonce, json.dumps(record).encode("utf-8"), b"log")
        sealed_b64 = base64.b64encode(sealed)

        with open(self.log_path, "ab") as f:
            f.write(sealed_b64 + b"\n")

        return ArtifactRecord(
            ts=record["ts"],
            profile_id=record["profile_id"],
            policy_hash=record["policy_hash"],
            direction=record["direction"],
            seq=self._seq,
            envelope_hash=record["envelope_hash"],
            chain_hash=record["chain_hash"],
        )
