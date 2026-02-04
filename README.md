# Adaptive DCF Firewall (Prototype)

A dynamic firewall that extends ideas from your DCF repo:
- Destination-aware risk scoring (uses your `policy_engine`, or `policy_engine_adapter`).
- Dynamic actions: allow / drop / rate-limit / quarantine.
- TLS SNI & JA3 fingerprinting (minimal, no external TLS libs).
- UNIX socket control API (`/var/run/adfw.sock`) to block IPs or JA3 on the fly.
- Optional Suricata integration to auto-block on alerts.

## 0) Install Prereqs (Ubuntu)
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv libpcap-dev iptables suricata
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 1) NFQUEUE rules (example)
```bash
# Intercept forwarded traffic (gateway/router)
sudo iptables -I FORWARD -j NFQUEUE --queue-num 1
# (Optional) Intercept local egress
# sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
```

## 2) Run the firewall
```bash
sudo python3 adaptive_firewall.py
```

Logs are JSON to stdout.

## 3) Control API examples
```bash
# Block an IP
python - <<'PY'
import socket, json
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("/var/run/adfw.sock")
s.send(json.dumps({"cmd":"block_ip","ip":"203.0.113.10"}).encode()); print(s.recv(4096))
PY

# Deny a JA3
python - <<'PY'
import socket, json
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("/var/run/adfw.sock")
s.send(json.dumps({"cmd":"deny_ja3","ja3":"d41d8cd98f00b204e9800998ecf8427e"}).encode()); print(s.recv(4096))
PY
```

## 4) Use your repo's policy engine
Place your `policy_engine.py` next to `adaptive_firewall.py` or install it as a module.
If your engine exposes different APIs, adapt `policy_engine_adapter.py` or add a wrapper method:
`score_destination(dst_ip, ctx) -> (score[0..1], action, reasons[])`.

## 4.5) Payload Crypto Layer (opt-in)
This repo now includes a policy-driven payload encryption layer that treats the tunnel as untrusted plumbing.
It is **disabled by default** to avoid breaking traffic. Enable only when both endpoints are crypto-aware.

Profiles live in `profiles/`:
- `profiles/default.yaml` (baseline)
- `profiles/elevated.yaml` (escalated threat posture)

Keys are loaded from environment variables:
- `ADCF_KEY_<KEY_ID>`: hex-encoded 32-byte key
- `ADCF_LOG_KEY`: hex-encoded 32-byte key for sealed artifact logs

To enable the payload crypto wrapper, set `PAYLOAD_CRYPTO_ENABLED = True` in `adaptive_firewall.py`
and ensure both sides can decrypt the envelope format.
Note: TCP stream reassembly is not implemented here; encryption is per-packet payload. For full TCP
correctness, wrap at a stream boundary or integrate a user-space proxy.

### TCP stream wrapper (hybrid mode)
Use `tcp_record_proxy.py` to apply the payload-crypto layer to a true TCP stream:
```bash
# Example: listen locally and forward to upstream
python tcp_record_proxy.py --listen 127.0.0.1:8443 --connect 203.0.113.10:443 --profile baseline
```
This proxy frames envelopes so the remote end can decrypt reliably.

### SOC triggers / hot reload
Control socket supports additional commands:
- `{"cmd":"reload_profiles"}`
- `{"cmd":"set_profile","profile_id":"elevated"}`
- `{"cmd":"clear_profile_override"}`

### Baseline learning + dynamic mitigation
The firewall now maintains a lightweight EWMA baseline per flow to detect anomalous rates.
If the anomaly score exceeds the profile threshold, it auto-escalates to the `elevated` profile,
which enables padding/pacing per your YAML configuration.

### Sealed log replay
Use `artifact_replay.py` to verify hash-chain integrity and decrypt sealed log records:
```bash
python artifact_replay.py --log logs/payload_artifacts.log --log-key-hex <32-byte-hex>
```

### Self-test
Run the local end-to-end test (echo server + proxy + client):
```bash
python scripts/self_test_unix.py
```

### Unit tests
```bash
pytest -q
```

### Combined test runner
```bash
scripts/run_tests.sh
```

### Test harness
```bash
python scripts/test_harness.py
```

### Mock SOC trigger test
```bash
python scripts/mock_soc_test.py
```

## 5) Suricata integration
- Ensure `eve.json` is enabled.
- Add `suricata/custom.rules` to your ruleset.
- Run the bridge which reads `eve.json` and issues control socket commands:
```bash
sudo python3 suricata_bridge.py --eve /var/log/suricata/eve.json --threshold 1
```

## 6) Docker
```bash
docker build -t adcfw .
docker run --rm --network host --cap-add NET_ADMIN -v /var/run:/var/run adcfw
```
Create NFQUEUE iptables rules on the host.

## 7) systemd install
```bash
sudo mkdir -p /opt/adcfw
sudo cp -r * /opt/adcfw/
sudo cp adaptive-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now adaptive-firewall.service
```

## 8) Testing
- Use `curl` to random hosts; watch logs for SNI, JA3 hashes.
- Try `telnet` to port 23 or `rdp` to 3389 to trigger rules.
- Use the control API to block and then un-block an IP and confirm behavior.

## Security Notes
- Prototype; NFQUEUE + Python can be CPU-heavy. Consider eBPF/XDP for production.
- Quarantine currently drops packets; replace with DNAT to a proxy if needed.
- Harden control socket permissions and authentication in production.
