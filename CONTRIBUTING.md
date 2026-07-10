# Contributing

Contributions are welcome when they preserve the project's authorized-use guardrails.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

## Required checks

```bash
ruff format --check .
ruff check .
python -m coverage run -m unittest discover -v
python -m coverage report
bandit -q -ll -r . -x ./.venv,./test_autonmap.py,./test_decrypt.py,./test_kali_ai_scan.py,./test_recon_planner.py,./test_tool_inventory.py
pip-audit -r requirements.txt
```

Add regression tests for behavior changes. Never include real targets, secrets, scan output,
or exploit payloads in commits or issues.
