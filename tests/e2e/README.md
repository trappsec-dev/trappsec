## end-to-end test suite
This directory contains Python-based end-to-end (E2E) tests that validate **all** trappsec packages, regardless of the language or framework used in the implementation.

These tests are designed to be run against the programs in the `examples/` directory. All example programs currently conform to a **shared, unified specification**, which allows the same E2E test suite to be reused across implementations.

### Running the Tests

When running an example program by hand against this suite, point its webhook at the suite's receiver and give both the same signing secret:

```bash
export TRAPPSEC_WEBHOOK_SECRET=dev-secret      # read by every example
python examples/flask/app.py --webhook=http://127.0.0.1:5050/webhook
pytest tests/e2e/test_example.py --url=http://127.0.0.1:8000   # also reads $TRAPPSEC_WEBHOOK_SECRET
```

The examples register the webhook with `alerts_only=False`, so the suite sees both `alert` and `signal` events. Every delivery is checked:

- its HMAC signature must verify against the secret (when one is set);
- it must carry exactly the keys in `tests/conformance/event_keys.json`, with sane values;
- each test waits for the expected number of events and then a short settle period, so a duplicate event fails the test;
- "no alert" checks end with a flush barrier: a trap hit with a fresh user agent whose event must arrive, which proves anything queued earlier was already delivered.

Pass `--unsupported=multipart` for an app whose multipart echo route returns `{"supported": false}`; those tests are then reported as skipped. Without the flag such a response fails the test.

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

The harness generates a fresh signing secret per run, waits for each app to answer HTTP before testing it, and reads results from pytest's JUnit XML. When `--log-dir` is given, per-case app logs (`<case>.app.log`), pytest output (`<case>.pytest.log`), `summary.csv` and `summary.txt` are written there. Without it, app output is discarded.

### Requirements

Python 3.10+ with `pytest` and `requests`; `uv` (the Python examples declare inline dependencies and run with `uv run`); Node 20+ and npm; Go 1.26+ (as required by `packages/go/go.mod`).
