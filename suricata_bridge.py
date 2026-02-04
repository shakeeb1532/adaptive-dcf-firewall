#!/usr/bin/env python3
# suricata_bridge.py
"""
Tail Suricata eve.json and send block/quarantine commands to the firewall control socket.
Usage:
  python suricata_bridge.py --eve /var/log/suricata/eve.json --threshold 1
"""
import argparse, json, socket, time, os, sys

CONTROL_SOCK = "/var/run/adfw.sock"

def send_cmd(obj):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(CONTROL_SOCK)
        s.send(json.dumps(obj).encode("utf-8"))
        resp = s.recv(4096)
        s.close()
        return resp
    except Exception as e:
        print(f"[bridge] control error: {e}", file=sys.stderr)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", default="/var/log/suricata/eve.json")
    ap.add_argument("--threshold", type=int, default=1, help="alerts to trigger block")
    args = ap.parse_args()

    counts = {}
    with open(args.eve, "r", encoding="utf-8", errors="ignore") as f:
        # naive tail -F
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5); continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get("event_type") == "alert":
                src = ev.get("src_ip"); dst = ev.get("dest_ip")
                sig = ev.get("alert", {}).get("signature_id")
                key = (src, dst, sig)
                counts[key] = counts.get(key, 0) + 1
                if counts[key] >= args.threshold and dst:
                    print(f"[bridge] blocking {dst} due to Suricata alert {sig}")
                    send_cmd({"cmd":"block_ip","ip": dst})

if __name__ == "__main__":
    main()
