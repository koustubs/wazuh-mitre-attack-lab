"""Retention failure and rerun checks. No running indexer or credentials required."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("retention", Path(__file__).resolve().parents[1] / "manager/configure-retention.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
POLICY = "wazuh-lab-retention"
NAME = "wazuh-alerts-4.x-2026.09.22"
MANAGED = {NAME: {"policy_id": POLICY, "enabled": True}}


class FakeIndexer:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if not self.responses:
            raise AssertionError("Unexpected API call")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class RetentionTests(unittest.TestCase):
    def run_config(self, responses):
        api = FakeIndexer(responses)
        output = io.StringIO()
        with redirect_stdout(output), patch.object(R.time, "sleep"):
            R.configure(api, 90)
        self.assertEqual(api.responses, [])
        return api, output.getvalue()

    def prefix(self):
        return [(200, {"status": "yellow", "timed_out": False}), (200, R.policy_body(90))]

    def test_existing_attachment_is_idempotent(self):
        api, output = self.run_config(self.prefix() + [(200, MANAGED), (200, MANAGED)])
        self.assertTrue(all(c[0] == "GET" for c in api.calls))
        self.assertIn("already attached", output)

    def test_no_alert_indices(self):
        _, output = self.run_config(self.prefix() + [(200, {}), (200, {})])
        self.assertIn("no existing alert indices", output)

    def test_create_missing_policy_then_attach(self):
        api, output = self.run_config([self.prefix()[0], (404, {"error": "not found"}),
            (201, {"_id": POLICY}), (200, R.policy_body(90)), (200, {NAME: {}}),
            (200, {"updated_indices": 1, "failures": False, "failed_indices": []}), (200, MANAGED)])
        self.assertEqual([c[0] for c in api.calls], ["GET", "GET", "PUT", "GET", "GET", "POST", "GET"])
        self.assertIn("attached to 1", output)

    def test_lookup_failure_does_not_create(self):
        api = FakeIndexer([self.prefix()[0], (403, {"error": "forbidden"})])
        with self.assertRaises(R.RetentionError):
            R.configure(api, 90)
        self.assertNotIn("PUT", [c[0] for c in api.calls])

    def test_cluster_timeout_is_not_ready(self):
        with self.assertRaises(R.RetentionError), patch.object(R.time, "sleep"):
            R.configure(FakeIndexer([(200, {"status": "red", "timed_out": True})] * 12), 90)

    def test_timeout_then_yellow(self):
        self.run_config([(408, {"status": "red", "timed_out": True})]
                        + self.prefix() + [(200, MANAGED), (200, MANAGED)])

    def test_attachment_error_and_partial_failure(self):
        for result in [(503, {"error": "unavailable"}),
                       (200, {"updated_indices": 0, "failures": True, "failed_indices": [NAME]}),
                       (200, {"updated_indices": 1, "failures": False}),
                       (200, {"updated_indices": True, "failures": False, "failed_indices": []})]:
            with self.subTest(result=result), self.assertRaises(R.RetentionError):
                self.run_config(self.prefix() + [(200, {NAME: {}}), result])

    def test_zero_updates_does_not_hide_unmanaged_index(self):
        with self.assertRaisesRegex(R.RetentionError, "not confirmed"):
            self.run_config(self.prefix() + [(200, {NAME: {}}),
                (200, {"updated_indices": 0, "failures": False, "failed_indices": []}), (200, {NAME: {}})])

    def test_readback_detects_false_success(self):
        with self.assertRaisesRegex(R.RetentionError, "not confirmed"):
            self.run_config(self.prefix() + [(200, {NAME: {}}),
                (200, {"updated_indices": 1, "failures": False, "failed_indices": []}), (200, {NAME: {}})])

    def test_other_policy_and_disabled_policy_are_preserved(self):
        for state in [{"policy_id": "other"}, {"policy_id": POLICY, "enabled": False}]:
            api = FakeIndexer(self.prefix() + [(200, {NAME: state})])
            with self.subTest(state=state), self.assertRaises(R.RetentionError):
                R.configure(api, 90)
            self.assertTrue(all(c[0] == "GET" for c in api.calls))

    def test_changed_retention_age_requires_review(self):
        with self.assertRaisesRegex(R.RetentionError, "differs"):
            self.run_config([self.prefix()[0], (200, R.policy_body(30))])

    def test_server_metadata_is_accepted(self):
        body = R.policy_body(90)
        body["policy"]["ism_template"][0]["last_updated_time"] = 12345
        body["policy"]["states"][1]["actions"][0]["retry"] = {"count": 3}
        R.check_policy(body, R.policy_body(90))

    def test_create_conflict_is_read_back(self):
        self.run_config([self.prefix()[0], (404, {}), (409, {"error": "exists"}),
                         (200, R.policy_body(90)), (200, MANAGED), (200, MANAGED)])

    def test_transport_retries_then_succeeds(self):
        for first in [subprocess.CompletedProcess([], 7, "\n000", "refused"),
                      subprocess.CompletedProcess([], 0, '{"error":"recovering"}\n503', "")]:
            with (self.subTest(first=first), patch.object(R.subprocess, "run", side_effect=[
                first, subprocess.CompletedProcess([], 0, '{"policy":{}}\n200', "")]) as run,
                patch.object(R.time, "sleep")):
                self.assertEqual(R.Indexer("https://localhost", "/certs").request("GET", "/policy")[0], 200)
                self.assertEqual(run.call_count, 2)

    def test_exhausted_retries_are_failure(self):
        with (patch.object(R.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, '{}\n503', "")) as run,
                patch.object(R.time, "sleep"), self.assertRaises(R.RetentionError)):
            R.Indexer("https://localhost", "/certs").request("GET", "/policy")
        self.assertEqual(run.call_count, 5)

    def test_authentication_and_bad_json_not_retried(self):
        for response in ['{}\n401', '<html>error</html>\n200']:
            with self.subTest(response=response), patch.object(R.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, response, "")) as run, self.assertRaises(R.RetentionError):
                R.Indexer("https://localhost", "/certs").request("GET", "/policy")
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
