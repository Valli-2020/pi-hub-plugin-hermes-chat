"""Schema, migration and config-change tests for the hermes plugin."""
import importlib.util
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Point PIHUB_DEV at a Pi Hub >= 8.3.0 checkout (the core, for pi_hub.plugins).
DEV = os.environ.get("PIHUB_DEV") or os.path.join(ROOT, "..", "pi-hub-dev")
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(ROOT, "pi_hub_plugins"))

from pi_hub.plugins import contrib  # noqa: E402
import hermes  # noqa: E402


def make():
    p = hermes.HermesPlugin()
    cfg = {}

    class Ctx:
        def get_config(self):
            return cfg

        def toast(self, *a, **k):
            pass

    p.ctx = Ctx()
    p._cfg = cfg
    p._lock = threading.Lock()
    p._sessions = {"u": "s1"}
    p._history = {}
    p._wake = threading.Event()
    p._gw = None
    return p


needs_list = pytest.mark.skipif(
    "list" not in getattr(contrib, "CONFIG_FIELD_TYPES", getattr(contrib, "FIELD_TYPES", ())),
    reason="core contrib lacks 'list' in FIELD_TYPES (pre-8.3.0 dev tree)")
needs_url = pytest.mark.skipif(
    "url" not in getattr(contrib, "CONFIG_FIELD_TYPES", getattr(contrib, "FIELD_TYPES", ())),
    reason="core contrib lacks 'url' in FIELD_TYPES (pre-8.3.0 dev tree)")


@needs_url
def test_schema_validates_and_keeps_every_field():
    schema = make().get_config_schema()
    out = contrib.validate_config_schema(schema)
    assert [f["name"] for f in out] == [f["name"] for f in schema]
    assert any(f["type"] == "password" for f in out)


@needs_url
def test_defaults_coerce():
    p = make()
    schema = contrib.validate_config_schema(p.get_config_schema())
    vals = {f["name"]: f["default"] for f in p.get_config_schema()}
    new, err = contrib.coerce_config_values(schema, vals, {})
    assert err is None
    assert new["timeout_seconds"] == 180


def test_schema_matches_shipped_config_and_manifest():
    import json
    d = os.path.join(ROOT, "pi_hub_plugins", "hermes")
    shipped = json.load(open(os.path.join(d, "config.json")))
    names = {f["name"] for f in make().get_config_schema()}
    assert set(shipped) == names
    man = json.load(open(os.path.join(d, "pihub-plugin.json")))
    assert man["version"] == hermes.HermesPlugin.version
    assert man["capabilities"] == hermes.HermesPlugin.capabilities
    assert man["min_core_version"] == hermes.HermesPlugin.min_core_version
    assert man["plugin_api_version"] == hermes.HermesPlugin.plugin_api_version


def test_migrate_old_config():
    old = {"hermes_url": "http://example.local:9119", "username": "u",
           "password": "secret-x", "timeout_seconds": "240"}
    out = make().migrate_config("0.1.0", old)
    assert out["hermes_url"] == "http://example.local:9119"
    assert out["username"] == "u" and out["password"] == "secret-x"
    assert out["timeout_seconds"] == 240
    assert out["history_limit"] == 40 and out["env_path"] == "~/.hermes/.env"
    assert out["tab_label"] == "Hermes"
    # idempotent
    assert make().migrate_config("0.2.0", out) == out


def test_migrate_garbage_falls_back():
    out = make().migrate_config("0.1.0", {"hermes_url": "", "timeout_seconds": None})
    assert out["hermes_url"] == hermes.DEFAULT_URL
    assert out["timeout_seconds"] == 180


def test_on_config_change_reconnects_only_on_connection_keys():
    p = make()

    class GW:
        closed = False

        def close(self):
            self.closed = True

    gw = p._gw = GW()
    p.on_config_change({"timeout_seconds": 1}, {"timeout_seconds": 2})
    assert p._gw is gw and p._sessions and p._wake.is_set()
    p._wake.clear()
    p.on_config_change({"hermes_url": "http://a.example"}, {"hermes_url": "http://b.example"})
    assert p._gw is None and gw.closed and not p._sessions and p._wake.is_set()


def test_history_settings_apply_live():
    p = make()
    p._cfg.update(history_limit=4, history_chars=50)
    for i in range(5):
        p._remember("u", "x" * 100, "y" * 100)
    log = p._history["u"]
    assert len(log) == 4 and len(log[0]["message"]) == 50


def test_env_path_used_for_credentials(tmp_path):
    f = tmp_path / "env"
    f.write_text("HERMES_DASHBOARD_BASIC_AUTH_USERNAME=a\nHERMES_DASHBOARD_BASIC_AUTH_PASSWORD=b\n")
    p = make()
    p._cfg.update(env_path=str(f), hermes_url="http://127.0.0.1:1")
    gw = p._build_gateway()
    assert (gw is not None)
    from hermes.auth import read_env_credentials
    assert read_env_credentials(str(f)) == ("a", "b")
