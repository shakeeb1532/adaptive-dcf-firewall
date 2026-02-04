# traffic_mitigation.py
"""
Deterministic padding and lightweight batching hooks.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import List


@dataclass
class PaddingPolicy:
    enabled: bool
    min_pad_bytes: int
    max_pad_bytes: int


@dataclass
class PacingPolicy:
    enabled: bool
    max_batch_bytes: int
    max_delay_ms: int


class DeterministicPadder:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def pad(self, payload: bytes, policy: PaddingPolicy) -> bytes:
        if not policy.enabled or policy.max_pad_bytes <= 0:
            return payload
        span = max(0, policy.max_pad_bytes - policy.min_pad_bytes)
        digest = hmac.new(self.key, hashlib.sha256(payload).digest(), hashlib.sha256).digest()
        pad_len = policy.min_pad_bytes + (digest[0] % (span + 1))
        if pad_len <= 0:
            return payload
        pad = digest[:pad_len] if pad_len <= len(digest) else (digest * (pad_len // len(digest) + 1))[:pad_len]
        # append pad length as 2 bytes (big-endian)
        return payload + pad + pad_len.to_bytes(2, "big")

    def unpad(self, payload: bytes) -> bytes:
        if len(payload) < 2:
            return payload
        pad_len = int.from_bytes(payload[-2:], "big")
        if pad_len <= 0 or pad_len + 2 > len(payload):
            return payload
        return payload[:-(pad_len + 2)]


class Batcher:
    def __init__(self, policy: PacingPolicy) -> None:
        self.policy = policy
        self._buf: List[bytes] = []
        self._size = 0
        self._last_flush = time.time()

    def push(self, payload: bytes) -> List[bytes]:
        if not self.policy.enabled:
            return [payload]

        now = time.time()
        self._buf.append(payload)
        self._size += len(payload)
        age_ms = (now - self._last_flush) * 1000.0
        if self._size >= self.policy.max_batch_bytes or age_ms >= self.policy.max_delay_ms:
            batch = b"".join(self._buf)
            self._buf = []
            self._size = 0
            self._last_flush = now
            return [batch]
        return []

    def flush(self) -> List[bytes]:
        if not self._buf:
            return []
        batch = b"".join(self._buf)
        self._buf = []
        self._size = 0
        self._last_flush = time.time()
        return [batch]


class Pacer:
    def __init__(self, policy: PacingPolicy) -> None:
        self.policy = policy
        self._last_send = 0.0

    def wait(self) -> None:
        if not self.policy.enabled or self.policy.max_delay_ms <= 0:
            return
        now = time.time()
        gap = self.policy.max_delay_ms / 1000.0
        if self._last_send == 0.0:
            self._last_send = now
            return
        elapsed = now - self._last_send
        if elapsed < gap:
            time.sleep(gap - elapsed)
        self._last_send = time.time()
