"""Shared cross-language cases from tests/conformance (R17, R18)."""
import json
import logging
import os
import pathlib
import sys

import pytest

try:
    import trappsec  # noqa: F401
except ImportError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec import Sentry, WatchBuilder
from trappsec.core import values_match

CONFORMANCE = pathlib.Path(__file__).resolve().parents[3] / "tests" / "conformance"


def _load(name):
    path = CONFORMANCE / name
    if not path.exists() and not os.environ.get("CI"):
        return [pytest.param(None, marks=pytest.mark.skip(reason=f"{name} not found (outside the trappsec repository)"))]
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def _bare_sentry():
    ts = Sentry.__new__(Sentry)  # skip framework registration
    ts.logger = logging.getLogger("trappsec-test")
    return ts


@pytest.mark.parametrize("case", _load("values_match.json"), ids=lambda c: f"{c['actual']!r}~{c['expected']!r}" if c else "missing")
def test_values_match(case):
    assert values_match(case["actual"], case["expected"]) is case["match"]


@pytest.mark.parametrize("case", _load("detect_honey_fields.json"), ids=lambda c: c["name"] if c else "missing")
def test_detect_honey_fields(case):
    source = case.get("source", "body")
    wb = WatchBuilder("/x")
    add = wb.query if source == "query" else wb.body
    for field, rule in case["rules"].items():
        if "default" in rule:
            add(field, default=rule["default"], intent=rule["intent"])
        else:
            add(field, intent=rule["intent"])
    built = wb.build()
    rules = built["query_fields"] if source == "query" else built["body_fields"]

    data, found, touched = _bare_sentry()._detect_honey_fields(case["data"], rules, None, source)

    expected = [dict(f, type=source) for f in case["found"]]
    key = lambda f: f["field"]  # noqa: E731
    assert sorted(found, key=key) == sorted(expected, key=key)
    assert data == case["result"]
    assert touched is case["touched"]
