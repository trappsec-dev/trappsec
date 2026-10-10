## end-to-end test suite
This directory contains Python-based end-to-end (E2E) tests that validate **all** trappsec packages, regardless of the language or framework used in the implementation.

These tests are designed to be run against the programs in the `examples/` directory. All example programs currently conform to a **shared, unified specification**, which allows the same E2E test suite to be reused across implementations.

### Running the Tests

When running an example program as part of the E2E test flow, make sure to include the following parameter so alert verification works correctly:

```bash
--webhook=http://localhost:5050/webhook
```

The E2E suite validates both `alert` and `signal` webhook events. If you run against a custom app config, ensure webhook integration is created with `alerts_only=False`.

### Run All Examples Sequentially

Use the harness below to run the shared E2E suite against all implementation examples one-by-one:

```bash
python tests/e2e/run_examples.py
```

Useful options:

```bash
# Run only selected cases
python tests/e2e/run_examples.py --cases node-koa,py-litestar,go-gin

# Increase startup timeout and write logs + summary.csv
python tests/e2e/run_examples.py --startup-timeout 90 --log-dir artifacts/e2e-matrix-logs

# Install Node example dependencies first (default: on when $CI is set)
python tests/e2e/run_examples.py --install

# Opt in to killing stray processes that hold the port (off by default)
python tests/e2e/run_examples.py --kill-port-blockers
```

When `--log-dir` is given, per-case app logs (`<case>.app.log`), pytest output (`<case>.pytest.log`), `summary.csv` and `summary.txt` are written there. Without it, app output is discarded.

### Requirements

Python 3.10+ with `pytest` and `requests`; `uv` (the Python examples declare inline dependencies and run with `uv run`); Node 18+ and npm; Go 1.25+.
