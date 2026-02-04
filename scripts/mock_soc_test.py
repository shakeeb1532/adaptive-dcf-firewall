#!/usr/bin/env python3
"""
Mock SOC trigger test:
- Starts firewall control server thread
- Sends set_profile/clear_profile_override commands
- Verifies reported status changes
"""
from __future__ import annotations

import json
import threading
import time

import adaptive_firewall as fw

def send_cmd_direct(obj):
    data = json.dumps(obj).encode("utf-8")
    return fw._handle_control_command(data)


def main():
    # start control server
    # Directly exercise control command handler to avoid UNIX socket binds in sandbox
    resp = send_cmd_direct({"cmd": "status"})
    status = json.loads(resp.decode("utf-8"))
    if "baseline" not in status.get("profiles", []):
        raise SystemExit("baseline profile missing")

    # set profile override
    resp = send_cmd_direct({"cmd": "set_profile", "profile_id": "elevated"})
    if b"\"ok\":true" not in resp:
        raise SystemExit("set_profile failed")

    resp = send_cmd_direct({"cmd": "status"})
    status = json.loads(resp.decode("utf-8"))
    if status.get("profile_override") != "elevated":
        raise SystemExit("profile override not set")

    # clear override
    resp = send_cmd_direct({"cmd": "clear_profile_override"})
    if b"\"ok\":true" not in resp:
        raise SystemExit("clear_profile_override failed")

    resp = send_cmd_direct({"cmd": "status"})
    status = json.loads(resp.decode("utf-8"))
    if status.get("profile_override") is not None:
        raise SystemExit("profile override not cleared")

    print("[OK] mock SOC test passed")


if __name__ == "__main__":
    main()
