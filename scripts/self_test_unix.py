#!/usr/bin/env python3
"""
End-to-end local self-test using socketpair (bind-free; works in locked sandboxes).
- Simulates a client->proxy->server pipeline
- Applies payload crypto on the proxy path
- Verifies echo round-trip
"""
from __future__ import annotations

import os
import socket
import threading
import time
import binascii

from profiles_loader import load_profiles
from payload_crypto import KeyStore, SequenceManager, encrypt_payload, decrypt_payload
from traffic_mitigation import PacingPolicy, Pacer
from stream_framing import frame_bytes, deframe


def _randkey() -> str:
    return binascii.hexlify(os.urandom(32)).decode("ascii")


def start_proxy(profile_id: str):
    profiles = load_profiles("profiles")
    profile = profiles[profile_id].raw
    policy_hash = profiles[profile_id].policy_hash
    keystore = KeyStore.from_env()
    seq_mgr = SequenceManager()

    pacing_cfg = profile.get("traffic_analysis", {}).get("pacing", {})
    pacing_policy = PacingPolicy(
        enabled=bool(pacing_cfg.get("enabled", False)),
        max_batch_bytes=int(pacing_cfg.get("max_batch_bytes", 0)),
        max_delay_ms=int(pacing_cfg.get("max_delay_ms", 0)),
    )
    pacer = Pacer(pacing_policy)

    def relay_plain_to_encrypted(src, dst):
        while True:
            data = src.recv(4096)
            if not data:
                break
            env = encrypt_payload(data, profile, profile_id, policy_hash, keystore, seq_mgr, "out", frame_plaintext=True)
            pacer.wait()
            dst.sendall(frame_bytes(env))

    def relay_encrypted_to_plain(src, dst):
        buf = b""
        while True:
            data = src.recv(4096)
            if not data:
                break
            buf += data
            frames, buf = deframe(buf)
            for env in frames:
                plain = decrypt_payload(env, profile, policy_hash, keystore, "in", frame_plaintext=True)
                pacer.wait()
                dst.sendall(plain)

    return relay_plain_to_encrypted, relay_encrypted_to_plain


def main():
    os.environ.setdefault("ADCF_KEY_K_BASE_OUT", _randkey())
    os.environ.setdefault("ADCF_KEY_K_BASE_OUT_2", _randkey())
    os.environ.setdefault("ADCF_KEY_K_HI_OUT", _randkey())
    os.environ.setdefault("ADCF_KEY_K_HI_OUT_2", _randkey())

    # Create socketpairs for client<->proxy and proxy<->server
    c_sock, p_in = socket.socketpair()
    p_out, s_sock = socket.socketpair()

    # Echo server on s_sock
    def server():
        while True:
            data = s_sock.recv(4096)
            if not data:
                break
            s_sock.sendall(data)
        s_sock.close()

    t_server = threading.Thread(target=server, daemon=True)
    t_server.start()

    relay_enc, relay_dec = start_proxy("baseline")
    t1 = threading.Thread(target=relay_enc, args=(p_in, p_out), daemon=True)
    t2 = threading.Thread(target=relay_dec, args=(p_out, p_in), daemon=True)
    t1.start(); t2.start()

    client = c_sock
    msg = b"hello-payload-crypto"
    client.sendall(msg)
    out = client.recv(4096)
    client.close()

    if out != msg:
        raise SystemExit("self-test failed: echo mismatch")

    print("[OK] unix self-test passed")


if __name__ == "__main__":
    main()
