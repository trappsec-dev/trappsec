# Contributing to trappsec

Thanks for helping. trappsec ships three parallel SDKs (Python, Node.js, Go) that must behave identically.

## Spec first

[`integration-rules.md`](integration-rules.md) is the specification for every framework integration. Read it before adding or changing an integration, and update it when you change behavior. A change that touches detection, events, delivery or traps should be made in all three languages (or explicitly documented as a known difference) with a regression test in each.

## Repository layout

| Path | Contents |
|---|---|
| `packages/python` | Python package (`pip install -e packages/python`) |
| `packages/node` | Node package; integration tests in `test/integrations` |
| `packages/go` | Go core module; adapters in `nethttp/`, `gin/`, `echo/` are separate modules |
| `examples/` | One runnable app per framework, all following one shared spec |
| `tests/e2e` | Black-box suite run against every example |
| `tests/conformance` | Shared JSON cases (value matching, detection, event keys) every SDK's unit tests load |
| `tests/package` | Builds the wheel, sdist and npm tarball and smoke-tests them installed |
| `docs/` | Jekyll site (https://trappsec.dev) |

## Development setup

### Python (3.10+)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e "packages/python[test,webhooks,otel]"
pip install flask fastapi httpx starlette django sanic sanic-testing tornado litestar opentelemetry-sdk requests pytest
pytest packages/python/tests
```

Integration tests skip when a framework is not installed.

### Node.js (20+)

```bash
cd packages/node
npm ci
npm test
cd test/integrations && npm ci && node --test
```

### Go (see `go.mod` for the version)

```bash
for m in packages/go packages/go/nethttp packages/go/gin packages/go/echo; do
  (cd $m && go vet ./... && go test -race ./...)
done
for d in examples/go-*/; do (cd $d && go build ./...); done
```

## End-to-end tests

The e2e harness starts each example, points its webhook at a local receiver and runs the shared pytest suite. You need Python 3.10+, `uv`, Node, npm and Go.

```bash
pip install pytest requests
python tests/e2e/run_examples.py --install --log-dir artifacts/e2e-logs
python tests/e2e/run_examples.py --cases py-flask,node-express   # subset
```

See [`tests/e2e/README.md`](tests/e2e/README.md) for options. If you add an example, add a case to `run_examples.py` (declare features it does not implement, e.g. `NO_MULTIPART`). Every example's `identify_user` must return `user` and `role`, and its webhook must read the signing secret from `TRAPPSEC_WEBHOOK_SECRET`.

## Conformance fixtures and package checks

[`tests/rule-coverage.md`](tests/rule-coverage.md) maps each integration rule to the tests that cover it per framework, with the open gaps. Update it when you add a framework or close a gap.

Matching, detection and event-shape rules that must agree across languages live in `tests/conformance/*.json`. Change behaviour there first; the Python, Node and Go unit tests all load those files.

`bash tests/package/run.sh` builds the Python and Node distributions, installs each into a clean environment outside the repo and runs a real app against it. Run it after touching packaging (`pyproject.toml`, `package.json` `files`/`exports`, `index.d.ts`, `index.mjs`).

## Pull requests

1. Open an issue for larger changes.
2. Add tests: every bug fix needs a regression test.
3. Update docs (`docs/`), `integration-rules.md` if behavior changes, and `CHANGELOG.md` under *Unreleased*.
4. CI (`.github/workflows/test.yml`) must pass.

## Releases

Publishing a GitHub release runs tests, then publishes PyPI (environment `pypi`) and npm (environment `npm`), and tags the Go modules in order: `packages/go/vX.Y.Z` first, then the `nethttp`, `gin` and `echo` adapters (see `go-tag.yml`).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
