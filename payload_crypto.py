# payload_crypto.py
"""
Policy-driven, multi-layer AEAD payload encryption with self-describing envelopes.
Tunnel is treated as untrusted plumbing; payloads remain encrypted beyond the tunnel.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from traffic_mitigation import DeterministicPadder, PaddingPolicy, PacingPolicy, Batcher
from stream_framing import frame_bytes, deframe


MAGIC = b"ADCF"  # Adaptive DCF Firewall
ENVELOPE_VERSION = 1


@dataclass
class Envelope:
    profile_id: str
    key_id: str
    epoch: int
    seq: int
    policy_hash: bytes
    ciphertext: bytes
    flags: int


class SequenceManager:
    def __init__(self) -> None:
        self._seq: Dict[Tuple[str, str], int] = {}

    def next(self, profile_id: str, direction: str) -> int:
        key = (profile_id, direction)
        self._seq[key] = self._seq.get(key, 0) + 1
        return self._seq[key]


class KeyStore:
    """
    Simple key store. In production this should be replaced by an HSM/KMS or secure
    control plane. Keys are expected to be random 32-byte values, hex-encoded.
    """
    def __init__(self, keys: Dict[str, bytes]) -> None:
        self._keys = keys

    @classmethod
    def from_env(cls, prefix: str = "ADCF_KEY_") -> "KeyStore":
        keys: Dict[str, bytes] = {}
        for k, v in os.environ.items():
            if k.startswith(prefix):
                key_id = k[len(prefix):].lower()
                keys[key_id] = bytes.fromhex(v)
        return cls(keys)

    def get(self, key_id: str) -> bytes:
        if key_id not in self._keys:
            raise KeyError(f"missing key_id: {key_id}")
        return self._keys[key_id]


def _derive_key(base_key: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(base_key)


def _deterministic_nonce(key: bytes, context: bytes) -> bytes:
    # 96-bit nonce derived from HMAC-SHA256 for deterministic, auditable behavior.
    return hmac.new(key, context, hashlib.sha256).digest()[:12]


def _get_aead(algo: str, key: bytes):
    algo = algo.lower()
    if algo == "chacha20-poly1305":
        return ChaCha20Poly1305(key)
    if algo in ("aes-256-gcm", "aes-gcm"):
        return AESGCM(key)
    raise ValueError(f"unsupported aead: {algo}")


def _epoch(rotate_seconds: int) -> int:
    return int(time.time()) // max(1, rotate_seconds)


def build_envelope(profile: Dict[str, Any], profile_id: str, key_id: str, epoch: int, seq: int,
                   policy_hash_hex: str, ciphertext: bytes, flags: int = 0) -> bytes:
    profile_id_b = profile_id.encode("utf-8")
    key_id_b = key_id.encode("utf-8")
    policy_hash = bytes.fromhex(policy_hash_hex)

    header = struct.pack(
        "!4sBBBBIQ32s",
        MAGIC,
        ENVELOPE_VERSION,
        flags,
        len(profile_id_b),
        len(key_id_b),
        epoch,
        seq,
        policy_hash,
    )
    return header + profile_id_b + key_id_b + ciphertext


def parse_envelope(data: bytes) -> Envelope:
    if len(data) < 4 + 1 + 1 + 1 + 1 + 4 + 8 + 32:
        raise ValueError("envelope too short")
    magic, version, flags, pid_len, kid_len, epoch, seq, policy_hash = struct.unpack(
        "!4sBBBBIQ32s", data[:4 + 1 + 1 + 1 + 1 + 4 + 8 + 32]
    )
    if magic != MAGIC or version != ENVELOPE_VERSION:
        raise ValueError("bad envelope header")
    off = 4 + 1 + 1 + 1 + 1 + 4 + 8 + 32
    profile_id = data[off:off + pid_len].decode("utf-8"); off += pid_len
    key_id = data[off:off + kid_len].decode("utf-8"); off += kid_len
    ciphertext = data[off:]
    return Envelope(profile_id=profile_id, key_id=key_id, epoch=epoch, seq=seq,
                    policy_hash=policy_hash, ciphertext=ciphertext, flags=flags)


def encrypt_payload(plain: bytes, profile: Dict[str, Any], profile_id: str, policy_hash_hex: str,
                    keystore: KeyStore, seq_mgr: SequenceManager, direction: str,
                    frame_plaintext: bool = True) -> bytes:
    layers: List[Dict[str, Any]] = profile["crypto"]["aead_layers"]
    flags = 0
    seq = seq_mgr.next(profile_id, direction)
    ct = plain
    last_key_id = ""
    rotate_secs = [int(layer.get("rotate_seconds", 300)) for layer in layers]
    epoch_val = _epoch(min(rotate_secs) if rotate_secs else 300)

    # Deterministic padding + lightweight batching (policy-driven)
    pad_cfg = profile.get("traffic_analysis", {}).get("padding", {})
    padding_policy = PaddingPolicy(
        enabled=bool(pad_cfg.get("enabled", False)),
        min_pad_bytes=int(pad_cfg.get("min_pad_bytes", 0)),
        max_pad_bytes=int(pad_cfg.get("max_pad_bytes", 0)),
    )
    padder = DeterministicPadder(keystore.get(str(layers[0]["key_id"]).lower()))
    ct = padder.pad(ct, padding_policy)

    pacing_cfg = profile.get("traffic_analysis", {}).get("pacing", {})
    pacing_policy = PacingPolicy(
        enabled=bool(pacing_cfg.get("enabled", False)),
        max_batch_bytes=int(pacing_cfg.get("max_batch_bytes", 0)),
        max_delay_ms=int(pacing_cfg.get("max_delay_ms", 0)),
    )
    batcher = Batcher(pacing_policy)
    batches = batcher.push(ct)
    if not batches:
        batches = [ct]
    ct = batches[0]

    # Frame for stream correctness (length-prefixed)
    if frame_plaintext:
        ct = frame_bytes(ct)

    for layer in layers:
        algo = layer["algo"]
        key_id = str(layer["key_id"]).lower()
        rotate_seconds = int(layer.get("rotate_seconds", 300))

        base_key = keystore.get(key_id)
        # Directional separation should be handled via distinct key_ids per direction.
        # Keep derivation stable across sender/receiver.
        info = f"{profile_id}|{key_id}|{epoch_val}".encode("utf-8")
        dkey = _derive_key(base_key, info)
        nonce = _deterministic_nonce(dkey, struct.pack("!IQ", epoch_val, seq))

        aead = _get_aead(algo, dkey)
        aad = policy_hash_hex.encode("ascii")
        ct = aead.encrypt(nonce, ct, aad)
        last_key_id = key_id

    return build_envelope(profile, profile_id, last_key_id, epoch_val, seq, policy_hash_hex, ct, flags)


def decrypt_payload(enveloped: bytes, profile: Dict[str, Any], policy_hash_hex: str,
                    keystore: KeyStore, direction: str,
                    frame_plaintext: bool = True) -> bytes:
    env = parse_envelope(enveloped)
    if env.policy_hash.hex() != policy_hash_hex:
        raise ValueError("policy hash mismatch")

    layers = list(reversed(profile["crypto"]["aead_layers"]))
    ct = env.ciphertext
    seq = env.seq

    for layer in layers:
        algo = layer["algo"]
        key_id = str(layer["key_id"]).lower()
        rotate_seconds = int(layer.get("rotate_seconds", 300))
        epoch_val = env.epoch  # enforce epoch from envelope

        base_key = keystore.get(key_id)
        info = f"{env.profile_id}|{key_id}|{epoch_val}".encode("utf-8")
        dkey = _derive_key(base_key, info)
        nonce = _deterministic_nonce(dkey, struct.pack("!IQ", epoch_val, seq))

        aead = _get_aead(algo, dkey)
        aad = policy_hash_hex.encode("ascii")
        ct = aead.decrypt(nonce, ct, aad)

    # Remove deterministic padding if present
    pad_cfg = profile.get("traffic_analysis", {}).get("padding", {})
    padding_policy = PaddingPolicy(
        enabled=bool(pad_cfg.get("enabled", False)),
        min_pad_bytes=int(pad_cfg.get("min_pad_bytes", 0)),
        max_pad_bytes=int(pad_cfg.get("max_pad_bytes", 0)),
    )
    if padding_policy.enabled:
        padder = DeterministicPadder(keystore.get(str(layers[-1]["key_id"]).lower()))
        ct = padder.unpad(ct)

    if frame_plaintext:
        frames, _rem = deframe(ct)
        if frames:
            return frames[0]
    return ct
