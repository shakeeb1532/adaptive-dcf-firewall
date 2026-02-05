#!/usr/bin/env python3
"""
Test harness that runs key checks and outputs a clear report.
"""
from __future__ import annotations

import os
import binascii
import subprocess
import sys
import time
import json
import socket

from profiles_loader import load_profiles
from payload_crypto import KeyStore, SequenceManager, encrypt_payload, decrypt_payload
from artifact_log import ArtifactLogger
from artifact_replay import main as replay_main
from stream_framing import frame_bytes


def _randkey() -> str:
    return binascii.hexlify(os.urandom(32)).decode("ascii")


def _print(name: str, ok: bool, detail: str = ""):
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}{' - ' + detail if detail else ''}")


def _setup_keys():
    os.environ.setdefault("ADCF_KEY_K_BASE_OUT", _randkey())
    os.environ.setdefault("ADCF_KEY_K_BASE_OUT_2", _randkey())
    os.environ.setdefault("ADCF_KEY_K_HI_OUT", _randkey())
    os.environ.setdefault("ADCF_KEY_K_HI_OUT_2", _randkey())
    os.environ.setdefault("ADCF_LOG_KEY", _randkey())


def test_crypto_roundtrip():
    _setup_keys()
    profiles = load_profiles("profiles")
    profile = profiles["baseline"].raw
    policy_hash = profiles["baseline"].policy_hash
    ks = KeyStore.from_env()
    seq = SequenceManager()

    pt = b"payload-data-123"
    env = encrypt_payload(pt, profile, "baseline", policy_hash, ks, seq, "out", frame_plaintext=True)
    out = decrypt_payload(env, profile, policy_hash, ks, "in", frame_plaintext=True)
    assert out == pt


def test_policy_hash_mismatch():
    _setup_keys()
    profiles = load_profiles("profiles")
    profile = profiles["baseline"].raw
    policy_hash = profiles["baseline"].policy_hash
    ks = KeyStore.from_env()
    seq = SequenceManager()

    pt = b"payload-data-123"
    env = encrypt_payload(pt, profile, "baseline", policy_hash, ks, seq, "out", frame_plaintext=True)
    bad_hash = "0" * 64
    try:
        decrypt_payload(env, profile, bad_hash, ks, "in", frame_plaintext=True)
    except Exception:
        assert True
        return
    assert False


def test_sealed_log_replay():
    _setup_keys()
    log_key = bytes.fromhex(os.environ["ADCF_LOG_KEY"])
    log_path = "logs/harness_payload_artifacts.log"
    if os.path.exists(log_path):
        os.remove(log_path)
    logger = ArtifactLogger(log_path, log_key)
    logger.write({"profile_id":"baseline","policy_hash":"x","direction":"out"}, b"env1")
    logger.write({"profile_id":"baseline","policy_hash":"x","direction":"out"}, b"env2")

    # Run replay tool via subprocess for real CLI path
    cmd = [sys.executable, "artifact_replay.py", "--log", log_path, "--log-key-hex", os.environ["ADCF_LOG_KEY"]]
    assert subprocess.call(cmd) == 0


def test_self_test_unix():
    cmd = [sys.executable, "scripts/self_test_unix.py"]
    assert subprocess.call(cmd) == 0


def main():
    _setup_keys()
    os.makedirs("logs", exist_ok=True)

    checks = [
        ("Crypto Roundtrip", test_crypto_roundtrip),
        ("Policy Hash Mismatch", test_policy_hash_mismatch),
        ("Sealed Log Replay", test_sealed_log_replay),
        ("Unix Self-Test", test_self_test_unix),
    ]

    passed = 0
    for name, fn in checks:
        try:
            ok = fn()
        except Exception as e:
            ok = False
            _print(name, ok, detail=str(e))
        else:
            _print(name, ok)
        if ok:
            passed += 1

    print(f"\nSummary: {passed}/{len(checks)} passed")
    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()
