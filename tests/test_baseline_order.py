"""Exercise chronological baseline previews through the real dashboard payload."""
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_adaptive_scoring import extract_baseline
from test_dashboard_scoring import build_script, run


class BaselineOrderTests(unittest.TestCase):
    def helper(self, folder):
        state = folder / 'baseline.json'
        script = extract_baseline().replace("STATE = '/var/lib/wazuh-lab/baseline.json'", 'STATE = ' + repr(str(state)))
        helper = folder / 'helper.py'
        helper.write_text(script, encoding='utf-8')
        return helper, state

    def call(self, helper, body):
        result = subprocess.run([sys.executable, str(helper)], input=json.dumps(body),
                                capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def test_preview_has_no_persistent_writes_or_same_window_leakage(self):
        with tempfile.TemporaryDirectory() as temp:
            helper, state = self.helper(Path(temp))
            observations = [{'agent': 'warm', 'epoch': e, 'hour': 10, 'rules': {'5501': 1}}
                            for e in [300, 600, 900]]
            self.call(helper, {'observations': observations[:1]})
            original = state.read_bytes()
            preview = self.call(helper, {'preview': True, 'observations': observations[1:]})
            self.assertEqual(state.read_bytes(), original)
            self.assertEqual(preview['before']['600']['warm']['windows'], 1)
            self.assertEqual(preview['before']['900']['warm']['windows'], 2)
            self.assertEqual(preview['agents']['warm']['windows'], 3)
            self.assertEqual(self.call(helper, {'preview': True, 'observations': observations[1:]}), preview)

    def test_recent_real_pipeline_history_can_discount_without_leaking_between_hosts(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            helper, state = self.helper(folder)
            start = dt.datetime(2026, 9, 22, 10, 0)
            records = []
            for i in range(34):
                stamp = (start + dt.timedelta(minutes=5*i, seconds=5)).isoformat() + '+0000'
                records.append({'timestamp': stamp, 'agent': {'name': 'warm'},
                                'rule': {'id': '5501', 'level': 3, 'description': 'Session opened'}})
                if i == 32:
                    records.append({'timestamp': stamp, 'agent': {'name': 'cold'},
                                    'rule': {'id': '5501', 'level': 3, 'description': 'Session opened'}})
            result = run(build_script(), records, folder, baseline=helper)['scoring']
            windows = {w['at']: w for w in result['windows']}
            self.assertEqual(windows['12:35']['working']['routine'], 0.65)
            self.assertEqual(windows['12:35']['working']['baselineWindows'], 31)
            self.assertEqual(windows['12:40']['working']['agent'], 'cold')
            self.assertEqual(windows['12:40']['working']['routine'], 1.0)
            self.assertEqual(windows['12:40']['working']['baselineWindows'], 0)
            persisted = json.loads(state.read_text())
            self.assertLess(persisted['agents']['warm']['lastWindow'], result['windows'][0]['epoch'])
            again = run(build_script(), records, folder, baseline=helper)['scoring']
            self.assertEqual(result['windows'], again['windows'])


if __name__ == '__main__':
    unittest.main()
