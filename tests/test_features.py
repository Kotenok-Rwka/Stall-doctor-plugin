"""Проверка журнала, смена версии приложения, вывод из «что помогло», отключение плагина системой."""
import json
import threading
import time
import types
from unittest.mock import MagicMock

from stubs import Checker, load

check = Checker()
new = load("sd_features")


def run():
    def mk():
        p = new.StallDoctorPlugin()
        p._rlang = 0
        p.issues = {}; p.issue_lock = threading.Lock(); p.cleared_at = 0
        p.last_log_ts = None; p.log_edge = set(); p.own_toggle = {}
        p.evs = []
        p.ev = lambda t, defer=False: p.evs.append(t)
        p._note_culprits = lambda n: None
        p._issue_expired = lambda e: False
        p._redact = lambda x, n=300: x
        p.stop = types.SimpleNamespace(wait=lambda t: False, is_set=lambda: False)
        return p

    # ---------- 1. проверка журнала
    class FakeLog:
        buf = []
        n = 0
        @classmethod
        def _w(cls, lvl, tag, msg):
            cls.n += 1
            cls.buf.append(f"11-10 12:00:00.{cls.n:03d}  4242  4343 {lvl} {tag}: {msg}")
        @classmethod
        def e(cls, tag, msg): cls._w("E", tag, msg)
        @classmethod
        def w(cls, tag, msg): cls._w("W", tag, msg)
    new.jclass = lambda name: FakeLog if name == "android.util.Log" else MagicMock()

    p = mk()
    noise = ["11-10 12:00:00.000   100   100 I SomeTag: hello", "garbage line"]
    p._read_logcat = lambda n=None: noise + FakeLog.buf + noise
    res = p._logcheck()
    for r in res: print("   ", r)
    check("logcheck: all 5 steps pass on a healthy pipeline", len(res) == 5 and all(x[1] for x in res), [r[0] for r in res if not r[1]])
    check("logcheck: no side effects (issues, cursor, edge)", p.issues == {} and p.last_log_ts is None and p.log_edge == set())

    p = mk(); FakeLog.buf = []
    p._read_logcat = lambda n=None: []
    res = dict((n, o) for n, o, _ in p._logcheck())
    check("logcheck: empty logcat is reported", res.get("logcat returns our line") is False and res.get("line format (threadtime) recognised") is False)

    p = mk(); FakeLog.buf = []
    orig_w = FakeLog._w
    p._read_logcat = lambda n=None: [l.replace("  4242  4343 ", " ") for l in FakeLog.buf]   # другой формат
    res = dict((n, o) for n, o, _ in p._logcheck())
    check("logcheck: unknown line format is reported", res.get("logcat returns our line") is True and res.get("line format (threadtime) recognised") is False
          and res.get("Python Traceback parsed, plugin named from file path") is False, res)

    def boom(*a): raise RuntimeError("no Log")
    new.jclass = lambda name: types.SimpleNamespace(e=boom, w=boom)
    res = mk()._logcheck()
    check("logcheck: write failure is reported", res and res[0][1] is False)
    new.jclass = lambda name: FakeLog

    # настоящий разбор не создаёт проблем из тестовых строк
    p = mk(); FakeLog.buf = []
    FakeLog.e("plugin.sdchk", "marker x"); 
    p._parse_log(list(FakeLog.buf), {"sdchk"})
    check("real scan ignores self-check lines", p.issues == {}, list(p.issues))

    # самопроверка включает logpipe и прогресс
    p = mk()
    p._logcheck = lambda: [("write to log", True, ""), ("parser", False, "x")]
    p._field_map = lambda *a, **k: {"lastPts": 0, "gettingDifference": 0}
    p._mc_fields = lambda acc: {"lastPts": 5, "lastSeq": 7, "gettingDifference": False}
    p._acc = lambda: 0
    p.hook_status = {}
    p._log = lambda t: None
    p._jset("app_ver", None)
    r = p._selfcheck()
    names = {n: o for n, o, _ in r}
    check("selfcheck: logpipe entries and progress check present", names.get("logpipe: parser") is False and names.get("progress fields readable (pts/seq)") is True, [n for n in names if "logpipe" in n or "progress" in n])
    check("selfcheck: failed logpipe goes to events", any("logpipe: parser" in e for e in p.evs))
    p._mc_fields = lambda acc: {"somethingElse": 1}
    r = p._selfcheck(); names = {n: o for n, o, _ in r}
    check("selfcheck: no pts fields -> flagged", names.get("progress fields readable (pts/seq)") is False)

    # ---------- 5. смена версии
    p = mk()
    res1 = [("A", True, ""), ("B", True, ""), ("hook X", True, ""), ("C", False, "")]
    p._app_ver = lambda: "12.10.6 (1)"
    p._app_version_check(res1)
    check("appver: first run only records", p._jget("app_change", None) is None and p._jget("app_ver", {}).get("app") == "12.10.6 (1)")
    p._app_ver = lambda: "13.1.1 (2)"
    res2 = [("A", True, ""), ("B", False, "gone"), ("hook X", False, ""), ("C", False, "")]
    p._app_version_check(res2)
    ch = p._jget("app_change", None)
    check("appver: change detected, lost = was OK and now FAIL (hooks and already-failing excluded)",
          ch and ch["a"] == "12.10.6 (1)" and ch["b"] == "13.1.1 (2)" and ch["lost"] == ["B"], ch)
    lines = p._app_change_lines()
    check("appver: lines for the report", len(lines) == 3 and "B" in lines[1] and "12.10.6" in lines[0], lines)
    p.selfcheck = res2; p._rlang = 0
    check("appver: selfcheck lines start with the change", p._selfcheck_lines()[0].startswith("Версия приложения изменилась"))
    p._app_version_check(res2)
    check("appver: same version again keeps the record", p._jget("app_change", None)["lost"] == ["B"])
    p2 = mk(); p2._app_ver = lambda: None; p2._app_version_check(res1)
    check("appver: no version -> nothing", p2._jget("app_ver", None) is None)
    p3 = mk(); p3._app_ver = lambda: "1 (1)"; p3._app_version_check(res1); p3._app_ver = lambda: "2 (2)"; p3._app_version_check(res1)
    p3._rlang = 0
    check("appver: change with nothing lost says so", "ничего не пропало" in p3._app_change_lines()[1])

    # ---------- 2. вывод из «что помогло»
    def setlog(p, entries): p._jset("recovery_log", [{"a": a, "ok": o} for a, o in entries])
    p = mk()
    setlog(p, [("reload", True), ("reload", True), ("reload", False), ("restart", True), ("restart", True)])
    v = p._recovery_verdict(); check("recovery: reload helps -> plugin logic", v and "Перезагрузка плагинов обычно помогает" in v, v)
    setlog(p, [("reload", False), ("reload", False), ("reload", False), ("restart", True), ("restart", True), ("restart", False)])
    v = p._recovery_verdict(); check("recovery: only restart helps -> client", v and "полный перезапуск помогает (2 из 3)" in v, v)
    setlog(p, [("reload", False), ("reload", True), ("restart", True), ("restart", False)])
    check("recovery: ambiguous -> no verdict", p._recovery_verdict() is None)
    setlog(p, [("reload", False), ("reload", False), ("restart", True)])
    check("recovery: too little data -> no verdict", p._recovery_verdict() is None)
    setlog(p, [])
    check("recovery: empty -> no verdict", p._recovery_verdict() is None)

    # ---------- 6. отключение системой
    def snap(prev_enabled, info, own=None):
        p = mk()
        p._plugins_info = lambda: [info]
        p._jset("plugin_snapshot", {"x": ["1.0", prev_enabled]})
        if own: p.own_toggle["x"] = own
        p._plugin_snapshot_check()
        return p, (p._jget("plugin_changes", []) or [])
    base = {"id": "x", "version": "1.0"}
    p, c = snap(True, dict(base, enabled=False, error="java.lang.IllegalStateException: boom", not_responding=False))
    check("sysdisabled: enabled->disabled with error", c and c[-1]["k"] == "sysdisabled" and "boom" in c[-1]["e"], c)
    p._rlang = 0
    check("sysdisabled: text in timeline", "отключён системой" in p._changes_lines(3600)[0], p._changes_lines(3600))
    p, c = snap(True, dict(base, enabled=False, error=None, not_responding=False))
    check("sysdisabled: no error -> plain 'disabled' (user toggle)", c and c[-1]["k"] == "disabled", c)
    p, c = snap(True, dict(base, enabled=False, error="boom", not_responding=False), own=time.time() - 60)
    check("sysdisabled: our own recent toggle is not blamed on the system", c and c[-1]["k"] == "disabled", c)
    p, c = snap(True, dict(base, enabled=False, error=None, not_responding=True))
    check("sysdisabled: not responding counts", c and c[-1]["k"] == "sysdisabled", c)
    p, c = snap(False, dict(base, enabled=True, error=None, not_responding=False))
    check("enabled stays 'enabled'", c and c[-1]["k"] == "enabled", c)
    # собственное выключение запоминается
    p = mk(); calls = []
    new.jclass = lambda name: types.SimpleNamespace(getInstance=lambda: types.SimpleNamespace(setPluginEnabled=lambda *a: calls.append(a)))
    p._plugin_set_enabled("zzz", False)
    check("own toggle recorded", "zzz" in p.own_toggle and calls)

    # ---------- помощник прогресса
    check("progress: numeric fields only", new.StallDoctorPlugin._progress_vals({"lastPts": 3, "lastSeq": 4, "flag": True, "name": "x", "dialogsLoadedTill": 9}) == (("dialogsLoadedTill", 9), ("lastPts", 3), ("lastSeq", 4)))
    check("progress: nothing -> None", new.StallDoctorPlugin._progress_vals({"flag": True}) is None and new.StallDoctorPlugin._progress_vals(None) is None)



def test_features():
    run()
    assert not check.fails, check.fails
