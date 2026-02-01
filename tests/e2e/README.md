## end-to-end test suite
This directory contains Python-based end-to-end (E2E) tests that validate **all** trappsec packages, regardless of the language or framework used in the implementation.

These tests are designed to be run against the programs in the `examples/` directory. All example programs currently conform to a **shared, unified specification**, which allows the same E2E test suite to be reused across implementations.

### Running the Tests

When running an example program as part of the E2E test flow, make sure to include the following parameter so alert verification works correctly:

```bash
--webhook=http://localhost:5050/webhook
```
