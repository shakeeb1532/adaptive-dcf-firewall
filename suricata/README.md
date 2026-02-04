# Suricata integration (quick notes)

1) Install Suricata and enable `eve.json` output.
2) Append `custom.rules` to your ruleset and include in `suricata.yaml`.
3) Run Suricata in AF_PACKET/pcap mode or on the egress interface.
4) Start the firewall (NFQUEUE) and the bridge script:
   - `sudo python3 adaptive_firewall.py`
   - `sudo python3 suricata_bridge.py --eve /var/log/suricata/eve.json --threshold 1`
