import os
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from test_all_functions import run_tests


class TestInstallerRuntime(unittest.TestCase):
    def test_full_runtime_suite(self):
        trace_path = os.environ.get("TTD_TEST_TRACE")
        self.assertTrue(trace_path, "TTD_TEST_TRACE must be set for the full runtime suite")
        self.assertTrue(Path(trace_path).exists(), f"Trace not found: {trace_path}")
        self.assertTrue(run_tests())


if __name__ == "__main__":
    unittest.main()
