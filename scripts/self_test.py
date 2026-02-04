#!/usr/bin/env python3
"""
End-to-end local self-test:
- Starts a local TCP echo server
- Starts the TCP record proxy (payload crypto)
- Sends traffic through the proxy and verifies echo
"""
from __future__ import annotations

import os
import socket
import threading
import time
import binascii

from profiles_loader import load_profiles
from payload_crypto import KeyStore, SequenceManager
from tcp_record_proxy import relay_plain_to_encrypted, relay_encrypted_to_plain
from traffic_mitigation import PacingPolicy, Pacer
from stream_framing import deframe


def _randkey() -> str:
    return binascii.hexlify(os.urandom(32)).decode("ascii")


def start_echo_server(host: str, port: int):
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, port))
    lsock.listen(5)

    def handler():
        while True:
            csock, _ = lsock.accept()
            def _serve():
                while True:
                    data = csock.recv(4096)
                    if not data:
                        break
                    csock.sendall(data)
                csock.close()
            threading.Thread(target=_serve, daemon=True).start()
    threading.Thread(target=handler, daemon=True).start()
    return lsock


def start_proxy(listen_host: str, listen_port: int, upstream_host: str, upstream_port: int, profile_id: str):
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

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((listen_host, listen_port))
    lsock.listen(5)

    def handler():
        while True:
            csock, _ = lsock.accept()
            rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            rsock.connect((upstream_host, upstream_port))
            t1 = threading.Thread(target=relay_plain_to_encrypted, args=(csock, rsock, profile, profile_id, policy_hash, keystore, seq_mgr, pacer), daemon=True)
            t2 = threading.Thread(target=relay_encrypted_to_plain, args=(rsock, csock, profile, policy_hash, keystore, pacer), daemon=True)
            t1.start(); t2.start()
    threading.Thread(target=handler, daemon=True).start()
    return lsock


def main():
    os.environ.setdefault("ADCF_KEY_K_BASE_OUT", _randkey())
    os.environ.setdefault("ADCF_KEY_K_BASE_OUT_2", _randkey())
    os.environ.setdefault("ADCF_KEY_K_HI_OUT", _randkey())
    os.environ.setdefault("ADCF_KEY_K_HI_OUT_2", _randkey())

    echo = start_echo_server("127.0.0.1", 9443)
    proxy = start_proxy("127.0.0.1", 9444, "127.0.0.1", 9443, "baseline")
    time.sleep(0.2)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9444))
    msg = b"hello-payload-crypto"
    client.sendall(msg)
    out = client.recv(4096)
    client.close()

    if out != msg:
        raise SystemExit("self-test failed: echo mismatch")

    echo.close()
    proxy.close()
    print("[OK] self-test passed")


if __name__ == "__main__":
    main()
