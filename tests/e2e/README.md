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

# Increase startup timeout and custom log folder
python tests/e2e/run_examples.py --startup-timeout 90 --log-dir artifacts/e2e-matrix-logs
```

Per-case app logs, pytest output, and a CSV summary are written under the log directory.
