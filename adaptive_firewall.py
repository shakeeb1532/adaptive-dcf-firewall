#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adaptive DCF Firewall
- NFQUEUE + Scapy packet interceptor
- Destination-aware scoring via your `policy_engine.score_destination()` if present
- Fallback heuristic engine
- TLS ClientHello SNI + JA3 fingerprint extraction (minimal parser)
- UNIX domain socket control API to accept JSON commands (block/quarantine/rate_limit)
- Structured JSON logs to stdout
"""
import json
import time
import logging
import socket
import threading
import os
from collections import defaultdict
from ipaddress import ip_address, ip_network

try:
    from netfilterqueue import NetfilterQueue
except Exception:
    NetfilterQueue = None
try:
    from scapy.all import IP, TCP
except Exception:
    IP = None
    TCP = None

from profiles_loader import load_profiles
from payload_crypto import KeyStore, SequenceManager, encrypt_payload, decrypt_payload
from artifact_log import ArtifactLogger
from traffic_baseline import TrafficBaseline

CONTROL_SOCK = os.environ.get("ADCFW_CONTROL_SOCK", "/var/run/adfw.sock")  # override for tests

try:
    import policy_engine  # expected in PYTHONPATH alongside this file or installed module
    HAVE_POLICY = hasattr(policy_engine, "score_destination")
except Exception:
    HAVE_POLICY = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# --- Dynamic state / policies ---
IP_BLACKLIST = set()
STATIC_IP_BLACKLIST = {"203.0.113.45"}
NETWORK_LOW_RISK = [ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"), ip_network("192.168.0.0/16")]
SUSPICIOUS_HOST_PATTERNS = ["login.", "secure.", "update.", "admin.", "free-"]

RATE_STATE = defaultdict(lambda: {"tokens": 10.0, "last": time.time()})
RATE_FILL = 2.0    # tokens per second
RATE_CAP = 30.0

# Baseline learning / anomaly detection
BASELINE = TrafficBaseline(alpha=0.2)

# --- Payload crypto (opt-in) -------------------------------------------------
PAYLOAD_CRYPTO_ENABLED = False  # enable only when both endpoints are crypto-aware
PROFILES_DIR = "profiles"
PROFILES = load_profiles(PROFILES_DIR)
SEQ_MGR = SequenceManager()
KEYSTORE = KeyStore.from_env()  # expects ADCF_KEY_<KEY_ID>=hex
LOG_KEY_HEX = os.environ.get("ADCF_LOG_KEY", "")
try:
    ARTIFACT_LOGGER = ArtifactLogger("logs/payload_artifacts.log", bytes.fromhex(LOG_KEY_HEX)) if LOG_KEY_HEX else None
except Exception:
    ARTIFACT_LOGGER = None
PROFILE_OVERRIDE = None
PROFILE_WATCH_INTERVAL = 2.0

def rate_check(key):
    st = RATE_STATE[key]
    now = time.time()
    delta = now - st["last"]
    st["tokens"] = min(RATE_CAP, st["tokens"] + delta * RATE_FILL)
    st["last"] = now
    if st["tokens"] >= 1.0:
        st["tokens"] -= 1.0
        return True
    return False

def is_internal(ip_str: str) -> bool:
    try:
        ip = ip_address(ip_str)
        return any(ip in net for net in NETWORK_LOW_RISK)
    except Exception:
        return False

def select_profile(dest_port: int, sni_host: str | None, score: float, anomaly_score: float) -> str:
    # Policy-driven escalation: start baseline, escalate if profile rules or score demand it.
    if PROFILE_OVERRIDE and PROFILE_OVERRIDE in PROFILES:
        return PROFILE_OVERRIDE
    profile_id = "baseline"
    baseline = PROFILES.get(profile_id)
    if not baseline:
        return next(iter(PROFILES.keys()))
    rules = baseline.raw.get("policy", {}).get("escalation", {})
    if sni_host:
        for pat in rules.get("on_sni_match", {}).get("patterns", []):
            if pat in sni_host:
                return rules.get("on_sni_match", {}).get("to_profile", profile_id)
    if dest_port in set(rules.get("on_port_match", {}).get("ports", [])):
        return rules.get("on_port_match", {}).get("to_profile", profile_id)
    anomaly_threshold = float(baseline.raw.get("traffic_analysis", {}).get("activation", {}).get("anomaly_threshold", 3.0))
    if anomaly_score >= anomaly_threshold:
        return "elevated" if "elevated" in PROFILES else profile_id
    if score >= 0.7:
        return "elevated" if "elevated" in PROFILES else profile_id
    return profile_id

def maybe_wrap_payload(sc, direction: str, profile_id: str, policy_hash: str):
    if not PAYLOAD_CRYPTO_ENABLED:
        return sc, None
    if not sc.haslayer(TCP):
        return sc, None
    tcp = sc.getlayer(TCP)
    payload = bytes(tcp.payload) if tcp.payload else b""
    if not payload:
        return sc, None
    if payload.startswith(b"ADCF"):
        return sc, None

    profile = PROFILES[profile_id].raw
    encrypted = encrypt_payload(payload, profile, profile_id, policy_hash, KEYSTORE, SEQ_MGR, direction)
    tcp.remove_payload()
    tcp.add_payload(encrypted)
    if sc.haslayer(IP):
        del sc[IP].len
        del sc[IP].chksum
    del tcp.chksum
    return sc, encrypted

def maybe_unwrap_payload(sc, direction: str, profile_id: str, policy_hash: str):
    if not PAYLOAD_CRYPTO_ENABLED:
        return sc, None
    if not sc.haslayer(TCP):
        return sc, None
    tcp = sc.getlayer(TCP)
    payload = bytes(tcp.payload) if tcp.payload else b""
    if not payload or not payload.startswith(b"ADCF"):
        return sc, None

    profile = PROFILES[profile_id].raw
    plain = decrypt_payload(payload, profile, policy_hash, KEYSTORE, direction)
    tcp.remove_payload()
    tcp.add_payload(plain)
    if sc.haslayer(IP):
        del sc[IP].len
        del sc[IP].chksum
    del tcp.chksum
    return sc, plain

# --- Minimal TLS ClientHello parser for SNI + JA3 ---------------------------
def parse_tls_client_hello(payload: bytes):
    """
    Returns (sni_host, ja3_string, ja3_hash) or (None, None, None) if not a ClientHello.
    JA3 string format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    """
    try:
        # TLS record header: ContentType(1)=22, Version(2), Length(2)
        if len(payload) < 5 or payload[0] != 22:
            return None, None, None
        rec_len = int.from_bytes(payload[3:5], "big")
        if 5 + rec_len > len(payload):
            # not enough bytes
            return None, None, None
        hs = payload[5:5+rec_len]
        if len(hs) < 4 or hs[0] != 1:  # Handshake Type 1 = ClientHello
            return None, None, None

        # Handshake header: type(1)=1, length(3)
        hs_len = int.from_bytes(hs[1:4], "big")
        body = hs[4:4+hs_len]
        if len(body) < 34:
            return None, None, None

        # ClientHello body:
        # version(2), random(32), session_id_len(1), session_id(?), cipher_suites_len(2), suites(?),
        # comp_methods_len(1), comp_methods(?), extensions_len(2), extensions(?)
        p = 0
        client_version = int.from_bytes(body[p:p+2], "big"); p += 2
        p += 32  # random
        if p >= len(body): return None, None, None
        sid_len = body[p]; p += 1
        p += sid_len
        if p + 2 > len(body): return None, None, None
        cs_len = int.from_bytes(body[p:p+2], "big"); p += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if p + i + 2 <= len(body):
                ciphers.append(str(int.from_bytes(body[p+i:p+i+2], "big")))
        p += cs_len
        if p >= len(body): return None, None, None
        comp_len = body[p]; p += 1
        p += comp_len
        if p + 2 > len(body): return None, None, None
        ext_len = int.from_bytes(body[p:p+2], "big"); p += 2
        exts_raw = body[p:p+ext_len]

        sni_host = None
        extensions = []
        elliptic_curves = []
        ec_point_formats = []

        q = 0
        while q + 4 <= len(exts_raw):
            etype = int.from_bytes(exts_raw[q:q+2], "big")
            elen = int.from_bytes(exts_raw[q+2:q+4], "big")
            q += 4
            edata = exts_raw[q:q+elen]
            q += elen
            extensions.append(str(etype))
            if etype == 0:  # server_name (SNI)
                # edata: list length(2), then entries
                if len(edata) >= 5:
                    l = int.from_bytes(edata[0:2], "big")
                    pos = 2
                    while pos + 3 <= len(edata):
                        stype = edata[pos]; pos += 1
                        slen = int.from_bytes(edata[pos:pos+2], "big"); pos += 2
                        s = edata[pos:pos+slen]; pos += slen
                        if stype == 0:  # host_name
                            try:
                                sni_host = s.decode("idna")
                            except Exception:
                                sni_host = s.decode("utf-8", errors="ignore")
            elif etype == 10:  # supported_groups (elliptic curves)
                if len(edata) >= 2:
                    l = int.from_bytes(edata[0:2], "big")
                    pos = 2
                    for i in range(0, l, 2):
                        if pos + i + 2 <= len(edata):
                            elliptic_curves.append(str(int.from_bytes(edata[pos+i:pos+i+2], "big")))
            elif etype == 11:  # ec_point_formats
                if len(edata) >= 1:
                    l = edata[0]
                    for i in range(l):
                        if 1+i <= len(edata):
                            ec_point_formats.append(str(edata[1+i]))

        # Build JA3 string
        ja3 = f"{client_version},{'-'.join(ciphers)},{'-'.join(extensions)},{'-'.join(elliptic_curves)},{'-'.join(ec_point_formats)}"
        ja3_hash = hashlib.md5(ja3.encode("ascii")).hexdigest()
        return sni_host, ja3, ja3_hash
    except Exception:
        return None, None, None

# need hashlib import for JA3
import hashlib

# --- Fallback scorer --------------------------------------------------------
def fallback_score(dest_ip: str, dest_port: int, payload: bytes, src_ip: str):
    score = 0.0
    reasons = []

    if dest_ip in STATIC_IP_BLACKLIST or dest_ip in IP_BLACKLIST:
        score = max(score, 0.99); reasons.append("ip-blacklist")

    # internal subnets considered low risk (adjust for your env)
    for net in NETWORK_LOW_RISK:
        try:
            if ip_address(dest_ip) in net:
                reasons.append("internal-net")
                score = min(score, 0.3)
                break
        except Exception:
            pass

    # suspicious legacy mgmt ports
    if dest_port in (23, 2323, 3389, 5900):
        score = max(score, 0.85); reasons.append("suspicious-port")

    host = None; ja3 = None; ja3_hash = None
    # Detect TLS for SNI/JA3
    if payload and payload[0] == 22:  # TLS Handshake record
        host, ja3, ja3_hash = parse_tls_client_hello(payload)
        if host:
            if any(pat in host for pat in SUSPICIOUS_HOST_PATTERNS):
                score = max(score, 0.8); reasons.append(f"suspicious-host:{host}")
            if len(host) > 60:
                score = max(score, 0.7); reasons.append("long-hostname")
        # Example: simple JA3 denylist hook (populate via control API)
        if ja3_hash and ja3_hash in JA3_DENYLIST:
            score = max(score, 0.95); reasons.append(f"ja3-deny:{ja3_hash}")

    action = "allow"
    if score >= 0.9: action = "drop"
    elif score >= 0.7: action = "quarantine"
    elif score >= 0.5: action = "rate_limit"

    return score, action, reasons, host, ja3_hash

# JA3 denylist (dynamic via control API)
JA3_DENYLIST = set()

# --- Control plane (UNIX socket) -------------------------------------------
def _handle_control_command(data: bytes) -> bytes:
    global PROFILES, PROFILE_OVERRIDE
    try:
        cmd = json.loads(data.decode("utf-8"))
        kind = cmd.get("cmd")
        if kind == "block_ip":
            ip = cmd.get("ip")
            if ip: IP_BLACKLIST.add(ip)
            return b'{"ok":true}\n'
        if kind == "unblock_ip":
            ip = cmd.get("ip")
            if ip: IP_BLACKLIST.discard(ip)
            return b'{"ok":true}\n'
        if kind == "deny_ja3":
            j = cmd.get("ja3")
            if j: JA3_DENYLIST.add(j)
            return b'{"ok":true}\n'
        if kind == "status":
            resp = {
                "blacklist": sorted(IP_BLACKLIST),
                "ja3_deny": sorted(JA3_DENYLIST),
                "profiles": sorted(PROFILES.keys()),
                "profile_override": PROFILE_OVERRIDE,
            }
            return (json.dumps(resp)+"\n").encode("utf-8")
        if kind == "reload_profiles":
            try:
                PROFILES = load_profiles(PROFILES_DIR)
                return b'{"ok":true}\n'
            except Exception:
                return b'{"ok":false,"err":"reload_failed"}\n'
        if kind == "set_profile":
            pid = cmd.get("profile_id")
            if pid in PROFILES:
                PROFILE_OVERRIDE = pid
                return b'{"ok":true}\n'
            return b'{"ok":false,"err":"unknown_profile"}\n'
        if kind == "clear_profile_override":
            PROFILE_OVERRIDE = None
            return b'{"ok":true}\n'
        return b'{"ok":false,"err":"unknown_cmd"}\n'
    except Exception:
        return b'{"ok":false,"err":"bad_json"}\n'


def control_server(sock_path: str | None = None):
    global PROFILES, PROFILE_OVERRIDE
    try:
        import os
        sock_path = sock_path or CONTROL_SOCK
        if os.path.exists(sock_path):
            os.remove(sock_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        os.chmod(sock_path, 0o666)  # relax for demo; harden in prod
        srv.listen(5)
        logging.info("Control socket listening at %s", sock_path)
        while True:
            conn, _ = srv.accept()
            with conn:
                data = conn.recv(8192)
                conn.send(_handle_control_command(data))
    except Exception as e:
        logging.error("Control server error: %s", e)

def profile_watcher():
    global PROFILES
    try:
        import os
        last_mtime = 0
        while True:
            try:
                mtime = max(os.path.getmtime(os.path.join(PROFILES_DIR, f)) for f in os.listdir(PROFILES_DIR))
                if mtime > last_mtime:
                    PROFILES = load_profiles(PROFILES_DIR)
                    last_mtime = mtime
                    logging.info("Profiles reloaded from disk")
            except Exception:
                pass
            time.sleep(PROFILE_WATCH_INTERVAL)
    except Exception as e:
        logging.error("Profile watcher error: %s", e)

def nfq_callback(pkt):
    try:
        sc = IP(pkt.get_payload())
    except Exception:
        pkt.drop(); return

    src = sc.src; dst = sc.dst
    if sc.haslayer(TCP):
        tcp = sc.getlayer(TCP)
        dport = tcp.dport
        payload = bytes(tcp.payload) if tcp.payload else b""
        anomaly_score = BASELINE.update(src, dst, dport, len(payload))

        # External policy engine first
        if HAVE_POLICY:
            try:
                ctx = {"src_ip": src, "dst_ip": dst, "dst_port": dport, "sample": payload[:256].hex()}
                res = policy_engine.score_destination(dst, ctx)
                if isinstance(res, (list, tuple)) and len(res) >= 3:
                    score, action, reasons = float(res[0]), str(res[1]), list(res[2])
                else:
                    raise ValueError("policy_engine returned unexpected shape")
                # apply decision
                if action == "rate_limit":
                    if not rate_check((src, dst, dport)):
                        logging.info(json.dumps({"event":"rate_drop","src":src,"dst":dst,"dport":dport,"reasons":reasons,"score":score}))
                        pkt.drop(); return
                    pkt.accept(); return
                if action == "quarantine":
                    logging.warning(json.dumps({"event":"quarantine","src":src,"dst":dst,"dport":dport,"reasons":reasons,"score":score}))
                    pkt.drop(); return
                if action == "drop":
                    logging.warning(json.dumps({"event":"drop","src":src,"dst":dst,"dport":dport,"reasons":reasons,"score":score}))
                    pkt.drop(); return
                # allow
                if PAYLOAD_CRYPTO_ENABLED:
                    profile_id = select_profile(dport, None, score, anomaly_score)
                    policy_hash = PROFILES[profile_id].policy_hash
                    direction = "out" if is_internal(src) and not is_internal(dst) else "in"
                    if direction == "out":
                        sc, encrypted = maybe_wrap_payload(sc, direction, profile_id, policy_hash)
                    else:
                        sc, _plain = maybe_unwrap_payload(sc, direction, profile_id, policy_hash)
                        encrypted = None
                    if encrypted and ARTIFACT_LOGGER:
                        ARTIFACT_LOGGER.write(
                            {"profile_id": profile_id, "policy_hash": policy_hash, "direction": direction},
                            encrypted,
                        )
                    pkt.set_payload(bytes(sc))
                pkt.accept(); return
            except Exception as e:
                logging.exception("policy_engine failure, using fallback: %s", e)

        # Fallback path with TLS SNI/JA3
        score, action, reasons, host, ja3_hash = fallback_score(dst, dport, payload, src)
        profile_id = select_profile(dport, host, score, anomaly_score)
        policy_hash = PROFILES[profile_id].policy_hash
        direction = "out" if is_internal(src) and not is_internal(dst) else "in"
        meta = {"event":"decision","src":src,"dst":dst,"dport":dport,"action":action,"score":round(score,2),"reasons":reasons,"profile":profile_id,"anomaly":round(anomaly_score,2)}
        if host: meta["sni"]=host
        if ja3_hash: meta["ja3"]=ja3_hash

        if action == "rate_limit":
            if not rate_check((src, dst, dport)):
                meta["event"]="rate_drop"; logging.info(json.dumps(meta)); pkt.drop(); return
            logging.info(json.dumps(meta)); pkt.accept(); return
        if action == "quarantine":
            logging.warning(json.dumps(meta)); pkt.drop(); return
        if action == "drop":
            logging.warning(json.dumps(meta)); pkt.drop(); return

        if PAYLOAD_CRYPTO_ENABLED and action == "allow":
            if direction == "out":
                sc, encrypted = maybe_wrap_payload(sc, direction, profile_id, policy_hash)
            else:
                sc, _plain = maybe_unwrap_payload(sc, direction, profile_id, policy_hash)
                encrypted = None
            if encrypted and ARTIFACT_LOGGER:
                ARTIFACT_LOGGER.write(
                    {"profile_id": profile_id, "policy_hash": policy_hash, "direction": direction},
                    encrypted,
                )
            pkt.set_payload(bytes(sc))

        logging.debug(json.dumps(meta)); pkt.accept(); return

    # Non-TCP: allow by default (extend as needed)
    pkt.accept()

def main():
    # start control server
    t = threading.Thread(target=control_server, daemon=True)
    t.start()
    # start profile watcher
    w = threading.Thread(target=profile_watcher, daemon=True)
    w.start()

    if NetfilterQueue is None:
        logging.error("netfilterqueue not available; install requirements and run as root for NFQUEUE")
        while True:
            time.sleep(1)

    nfq = NetfilterQueue()
    try:
        nfq.bind(1, nfq_callback)
        logging.info("Adaptive DCF Firewall active on NFQUEUE 1 (Ctrl+C to stop)")
        nfq.run()
    except KeyboardInterrupt:
        logging.info("Shutting down")
    finally:
        nfq.unbind()

if __name__ == "__main__":
    main()
