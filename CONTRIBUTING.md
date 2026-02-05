# Contributing

Thanks for your interest in improving Adaptive DCF Firewall.

## Development Setup
- Python 3.11+
- Install dependencies: `pip install -r requirements.txt`

## Running Tests
- `scripts/run_tests.sh`
- Or run individually:
  - `PYTHONPATH=. python -m pytest -q`
  - `PYTHONPATH=. python scripts/test_harness.py`
  - `PYTHONPATH=. python scripts/mock_soc_test.py`

## Pull Requests
- Keep changes focused and small when possible.
- Include tests for new behavior.
- Update docs when behavior changes.

## Security
If you find a security issue, please open a private report or contact the maintainer directly.
