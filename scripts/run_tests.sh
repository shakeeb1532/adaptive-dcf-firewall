#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH=.

echo "[RUN] pytest"
python3 -m pytest -q

echo "[RUN] unix self-test"
python3 scripts/self_test_unix.py

echo "[RUN] test harness"
python3 scripts/test_harness.py

echo "[RUN] mock SOC test"
python3 scripts/mock_soc_test.py
