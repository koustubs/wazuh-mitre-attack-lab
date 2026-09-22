#!/usr/bin/env python3
"""Apply the lab's retention policy through the public ISM API, then read it back."""
import json
import subprocess
import sys
import time
from urllib.parse import quote


class RetentionError(Exception):
    pass


class Indexer:
    def __init__(self, url, certs):
        self.url = url
        self.certs = certs

    def request(self, method, path, body=None):
        args = ["curl", "-sS", "--connect-timeout", "3", "--max-time", "15", "-k",
                "--cert", self.certs + "/admin.pem", "--key", self.certs + "/admin-key.pem",
                "-X", method, "-w", "\n%{http_code}", self.url + path]
        if body is not None:
            args += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
        # Cluster health does not establish plugin readiness. Retry the ISM operations too.
        for attempt in range(5):
            result = subprocess.run(args, input=json.dumps(body) if body is not None else None,
                                    capture_output=True, text=True)
            payload, _, code = result.stdout.rpartition("\n")
            status = int(code) if code.isdigit() else 0
            transient = result.returncode in (7, 28, 52, 56) or status in (429, 502, 503, 504)
            if transient and attempt < 4:
                time.sleep(2 ** (attempt + 1))
                continue
            if result.returncode:
                raise RetentionError(f"{method} {path}: connection failed (curl {result.returncode}).")
            if status >= 500 or status in (401, 403, 429):
                raise RetentionError(f"{method} {path}: HTTP {status}.")
            try:
                data = json.loads(payload)
            except ValueError:
                raise RetentionError(f"{method} {path}: invalid JSON (HTTP {status}).") from None
            if not isinstance(data, dict):
                raise RetentionError(f"{method} {path}: expected a JSON object.")
            return status, data


def require(status, data, codes, operation):
    if status not in codes or "error" in data:
        raise RetentionError(f"{operation} failed (HTTP {status}).")


def policy_body(days):
    return {"policy": {
        "description": f"Wazuh lab: delete alert indices after {days} days.",
        "default_state": "hot",
        "states": [
            {"name": "hot", "actions": [], "transitions": [
                {"state_name": "delete", "conditions": {"min_index_age": f"{days}d"}}]},
            {"name": "delete", "actions": [{"delete": {}}], "transitions": []}],
        "ism_template": [{"index_patterns": ["wazuh-alerts-*"], "priority": 100}]}}


def check_policy(data, expected):
    policy = data.get("policy", {})
    # Do not overwrite a different deletion policy or silently ignore a changed retention age.
    try:
        states = policy["states"]
        hot = next(state for state in states if state["name"] == "hot")
        delete = next(state for state in states if state["name"] == "delete")
        templates = policy["ism_template"]
        valid = (policy["default_state"] == "hot" and len(states) == 2
                 and hot["actions"] == []
                 and hot["transitions"] == expected["policy"]["states"][0]["transitions"]
                 and delete["transitions"] == [] and len(delete["actions"]) == 1
                 and delete["actions"][0].get("delete") == {}
                 and len(templates) == 1 and templates[0]["index_patterns"] == ["wazuh-alerts-*"]
                 and templates[0]["priority"] == 100)
    except (KeyError, TypeError, AttributeError, StopIteration):
        valid = False
    if not valid:
        raise RetentionError("Existing retention policy differs from the requested settings; review it before changing it.")


def explain(api):
    status, data = api.request("GET", "/_plugins/_ism/explain/wazuh-alerts-*")
    require(status, data, (200,), "Reading alert retention")
    indices = {}
    for name, state in data.items():
        if name == "total_managed_indices":
            continue
        if not name.startswith("wazuh-alerts-") or not isinstance(state, dict) or "error" in state:
            raise RetentionError("Unexpected response while reading alert retention.")
        indices[name] = state
    return indices


def assigned_policy(state):
    return (state.get("policy_id") or state.get("index.plugins.index_state_management.policy_id")
            or state.get("index.opendistro.index_state_management.policy_id"))


def configure(api, days):
    if not 1 <= days <= 36500:
        raise RetentionError("Retention days must be between 1 and 36500.")
    # Yellow is sufficient for primaries on a single-node lab, but a timed-out wait is not.
    for attempt in range(12):
        status, health = api.request("GET", "/_cluster/health?wait_for_status=yellow&timeout=10s")
        if status == 200 and health.get("status") in ("yellow", "green") and health.get("timed_out") is False:
            break
        if status not in (200, 408):
            raise RetentionError(f"Reading cluster health failed (HTTP {status}).")
        if attempt == 11:
            raise RetentionError("The indexer did not reach yellow; retention was not configured.")
        time.sleep(2)

    policy_id = "wazuh-lab-retention"
    path = "/_plugins/_ism/policies/" + policy_id
    expected = policy_body(days)
    status, data = api.request("GET", path)
    if status == 404:
        # Only a missing policy permits creation. Authentication and recovery errors do not.
        status, data = api.request("PUT", path, expected)
        # A timed-out create may have succeeded, making the retry conflict. Read it back.
        if status != 409:
            require(status, data, (200, 201), "Creating retention policy")
        status, data = api.request("GET", path)
    require(status, data, (200,), "Reading retention policy")
    check_policy(data, expected)

    before = explain(api)
    pending = []
    for name, state in before.items():
        policy = assigned_policy(state)
        if policy is None:
            pending.append(name)
        elif policy != policy_id or state.get("enabled") is False:
            raise RetentionError(f"{name} has a different or disabled retention policy; review it first.")

    updated = 0
    if pending:
        # Adding to already managed indices can report failures. Target only unmanaged ones.
        target = ",".join(quote(name, safe="") for name in pending)
        status, data = api.request("POST", "/_plugins/_ism/add/" + target, {"policy_id": policy_id})
        require(status, data, (200,), "Attaching retention policy")
        updated = data.get("updated_indices")
        if (data.get("failures") is not False or data.get("failed_indices") != []
                or type(updated) is not int or updated < 0 or updated > len(pending)):
            raise RetentionError("Retention attachment failed or returned an invalid result.")

    after = explain(api)
    if not set(before).issubset(after):
        raise RetentionError("The alert index list changed during retention verification; re-run tuning.")
    for name, state in after.items():
        if assigned_policy(state) != policy_id or state.get("enabled") is False:
            raise RetentionError(f"Retention attachment was not confirmed for {name}.")
    if not after:
        print("  retention policy ready; no existing alert indices")
    elif updated:
        print(f"  retention attached to {updated} indices; verified on {len(after)} indices")
    else:
        print(f"  retention already attached; verified on {len(after)} indices")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("Usage: configure-retention.py <indexer-url> <certificate-directory> <retention-days>")
    try:
        configure(Indexer(sys.argv[1], sys.argv[2]), int(sys.argv[3]))
    except (RetentionError, ValueError, OSError) as error:
        print(f"  Retention incomplete: {error}", file=sys.stderr)
        sys.exit(1)
