"""Run the standalone script-style suites (they exit non-zero on failure)."""
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.mark.parametrize("script", ["test_wsclient.py", "test_hardening.py"])
def test_script(script):
    # The plugin package imports pi_hub.plugins.base: point PIHUB_DEV at a core checkout.
    dev = os.environ.get("PIHUB_DEV") or os.path.join(HERE, "..", "..", "pi-hub-dev")
    env = dict(os.environ, PYTHONPATH=dev + os.pathsep + os.environ.get("PYTHONPATH", ""))
    r = subprocess.run([sys.executable, os.path.join(HERE, script)], env=env,
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
