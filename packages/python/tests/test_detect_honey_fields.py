import logging
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec.builders import NO_DEFAULT
from trappsec.core import Sentry


class _Dummy:
    logger = logging.getLogger("trappsec-test")


class DetectHoneyFieldsTests(unittest.TestCase):
    def test_touched_with_default_value_strips_without_violation(self):
        data = {"role": "user", "safe": "x"}
        rules = {"role": {"default": "user", "intent": "Privilege Escalation"}}

        sanitized, found, touched = Sentry._detect_honey_fields(_Dummy(), data, rules, None)

        self.assertTrue(touched)
        self.assertEqual(found, [])
        self.assertEqual(sanitized, {"safe": "x"})

    def test_touched_with_mismatch_strips_and_reports_violation(self):
        data = {"role": "admin", "safe": "x"}
        rules = {"role": {"default": "user", "intent": "Privilege Escalation"}}

        sanitized, found, touched = Sentry._detect_honey_fields(_Dummy(), data, rules, None)

        self.assertTrue(touched)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["field"], "role")
        self.assertEqual(sanitized, {"safe": "x"})

    def test_untouched_no_watched_keys_is_noop(self):
        data = {"safe": "x"}
        rules = {"role": {"default": "user", "intent": "Privilege Escalation"}}

        sanitized, found, touched = Sentry._detect_honey_fields(_Dummy(), data, rules, None)

        self.assertFalse(touched)
        self.assertEqual(found, [])
        self.assertEqual(sanitized, {"safe": "x"})

    def test_no_default_marks_violation_and_strips(self):
        data = {"token": "abc"}
        rules = {"token": {"default": NO_DEFAULT, "intent": "Credential Stuffing"}}

        sanitized, found, touched = Sentry._detect_honey_fields(_Dummy(), data, rules, None)

        self.assertTrue(touched)
        self.assertEqual(len(found), 1)
        self.assertEqual(sanitized, {})


if __name__ == "__main__":
    unittest.main()
