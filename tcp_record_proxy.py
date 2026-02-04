#!/usr/bin/env python3
"""
TCP record proxy that applies payload_crypto envelope on a stream.
Use when you need true TCP stream correctness (hybrid mode).
"""
from __future__ import annotations

import argparse
import socket
import threading

from profiles_loader import load_profiles
from payload_crypto import KeyStore, SequenceManager, encrypt_payload, decrypt_payload
from stream_framing import frame_bytes, deframe
from traffic_mitigation import PacingPolicy, Pacer


def relay_plain_to_encrypted(src, dst, profile, profile_id, policy_hash, keystore, seq_mgr, pacer: Pacer):
    while True:
        data = src.recv(4096)
        if not data:
            break
        env = encrypt_payload(data, profile, profile_id, policy_hash, keystore, seq_mgr, "out", frame_plaintext=True)
        pacer.wait()
        dst.sendall(frame_bytes(env))


def relay_encrypted_to_plain(src, dst, profile, policy_hash, keystore, pacer: Pacer):
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="listen host:port")
    ap.add_argument("--connect", required=True, help="upstream host:port")
    ap.add_argument("--profile", default="baseline")
    ap.add_argument("--profiles", default="profiles")
    args = ap.parse_args()

    profiles = load_profiles(args.profiles)
    if args.profile not in profiles:
        raise SystemExit(f"unknown profile: {args.profile}")
    profile = profiles[args.profile].raw
    policy_hash = profiles[args.profile].policy_hash
    pacing_cfg = profile.get("traffic_analysis", {}).get("pacing", {})
    pacing_policy = PacingPolicy(
        enabled=bool(pacing_cfg.get("enabled", False)),
        max_batch_bytes=int(pacing_cfg.get("max_batch_bytes", 0)),
        max_delay_ms=int(pacing_cfg.get("max_delay_ms", 0)),
    )
    pacer = Pacer(pacing_policy)

    keystore = KeyStore.from_env()
    seq_mgr = SequenceManager()

    lhost, lport = args.listen.split(":")
    rhost, rport = args.connect.split(":")

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((lhost, int(lport)))
    lsock.listen(5)

    while True:
        csock, _ = lsock.accept()
        rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rsock.connect((rhost, int(rport)))

        t1 = threading.Thread(target=relay_plain_to_encrypted, args=(csock, rsock, profile, args.profile, policy_hash, keystore, seq_mgr, pacer), daemon=True)
        t2 = threading.Thread(target=relay_encrypted_to_plain, args=(rsock, csock, profile, policy_hash, keystore, pacer), daemon=True)
        t1.start(); t2.start()


if __name__ == "__main__":
    main()
