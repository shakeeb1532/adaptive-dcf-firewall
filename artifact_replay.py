#!/usr/bin/env python3
"""
Verify and replay sealed artifact logs. Validates AEAD and hash-chain integrity.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def _nonce(log_key: bytes, chain: bytes, seq: int) -> bytes:
    return hmac.new(log_key, chain + seq.to_bytes(8, "big"), hashlib.sha256).digest()[:12]


def _canonical_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True, help="path to payload_artifacts.log")
    ap.add_argument("--log-key-hex", required=True, help="hex-encoded 32-byte log key")
    ap.add_argument("--limit", type=int, default=0, help="max records to print (0 = all)")
    args = ap.parse_args()

    log_key = bytes.fromhex(args.log_key_hex)
    aead = ChaCha20Poly1305(log_key)

    chain = b"\x00" * 32
    count = 0
    ok = True

    with open(args.log, "rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count += 1
            nonce = _nonce(log_key, chain, count)
            try:
                sealed = base64.b64decode(line)
                record_bytes = aead.decrypt(nonce, sealed, b"log")
            except Exception:
                ok = False
                print(f"[FAIL] record {count}: AEAD decrypt failed")
                break

            record = json.loads(record_bytes.decode("utf-8"))
            chain_prev = bytes.fromhex(record.get("chain_prev", ""))
            if chain_prev != chain:
                ok = False
                print(f"[FAIL] record {count}: chain_prev mismatch")
                break

            # Recompute chain hash from canonical record sans chain_hash
            record_for_hash = dict(record)
            record_for_hash.pop("chain_hash", None)
            encoded = _canonical_json(record_for_hash)
            chain = hashlib.sha256(chain + encoded).digest()
            if record.get("chain_hash") != chain.hex():
                ok = False
                print(f"[FAIL] record {count}: chain_hash mismatch")
                break

            if args.limit and count <= args.limit:
                print(json.dumps(record, indent=2, sort_keys=True))

    if ok:
        print(f"[OK] verified {count} records")


if __name__ == "__main__":
    main()
