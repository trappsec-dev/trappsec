#!/usr/bin/env bash
# Build the Python and Node distributions and smoke-test each one installed into
# a clean environment outside the repository, so packaging mistakes (a module
# missing from the wheel or the npm "files" list, a broken ESM entry point or
# index.d.ts) fail here instead of after a release.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/tests/package"
PYTHON="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== python: build wheel and sdist"
"$PYTHON" -m venv "$WORK/build-venv"
"$WORK/build-venv/bin/pip" install -q build
"$WORK/build-venv/bin/python" -m build -q --outdir "$WORK/dist" "$ROOT/packages/python"

for dist in "$WORK"/dist/*.whl "$WORK"/dist/*.tar.gz; do
  echo "== python: $(basename "$dist")"
  "$PYTHON" -m venv "$WORK/venv"
  "$WORK/venv/bin/pip" install -q "$dist" flask
  (cd "$WORK" && "$WORK/venv/bin/python" -I "$HERE/python_smoke.py")
  rm -rf "$WORK/venv"
done

echo "== node: npm pack"
(cd "$ROOT/packages/node" && npm pack --silent --pack-destination "$WORK" >/dev/null)
mkdir "$WORK/node"
cp "$HERE/node_smoke.cjs" "$HERE/node_smoke.mjs" "$HERE/types.ts" "$WORK/node/"
cd "$WORK/node"
npm init -y >/dev/null
npm install --silent --no-audit --no-fund "$WORK"/trappsec-*.tgz express @types/express @types/node typescript
node node_smoke.cjs
node node_smoke.mjs
npx --no-install tsc --noEmit --strict --esModuleInterop --skipLibCheck false --module node16 --moduleResolution node16 types.ts
echo "node package smoke ok (types)"
