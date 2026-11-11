"""Ядро обнаружения: пробы, курсор журнала, прогресс pts, склейка эпизодов, сопоставление плагинов."""
import collections
import threading
import time
import types
from unittest.mock import MagicMock

from stubs import Checker, load

check = Checker()
new = load("sd_core")


def run():
    # ---------- 1. Probe
    P = new.Probe("ping"); calls = []
    P.fire(lambda d: calls.append(d), 1000.0)
    check("probe: pending after fire", P.sent == 1000.0 and P.pending_for(1030.0) == 30.0)
    P.fire(lambda d: calls.append(d), 1060.0)
    check("probe: no refire before PROBE_LOST", len(calls) == 1)
    P.fire(lambda d: calls.append(d), 1100.0)
    check("probe: refire after PROBE_LOST, lost counted", len(calls) == 2 and P.lost == 1)
    check("probe: wait clock NOT reset (real freeze not masked)", P.pending_for(1100.0) == 100.0, P.pending_for(1100.0))
    calls[0]()   # запоздалый ответ старой пробы
    check("probe: late answer proves life", P.pending_for(1101.0) == 0.0)
    check("probe: newer probe still in flight", P.sent == 1100.0)
    calls[1]()
    check("probe: cleared after current answer", P.sent is None and P.last_latency is not None)
    P.fire(lambda d: calls.append(d), 2000.0); P.reset()
    check("probe: reset clears", P.sent is None and P.pending_for(2050.0) == 0.0)

    # ---------- 2. журнал
    def mk(mod):
        p = mod.StallDoctorPlugin()
        p.issues = {}; p.issue_lock = threading.Lock(); p.cleared_at = 0
        p.last_log_ts = None; p.log_edge = set()
        p.ev = lambda *a, **k: None
        p._note_culprits = lambda n: None
        p._issue_expired = lambda e: False
        p._redact = lambda x, n=300: x
        return p
    def L(ts, tag, msg, lvl="E", pid=10, tid=11):
        return f"{ts}  {pid}  {tid} {lvl} {tag}: {msg}"

    p = mk(new); ids = {"foo", "bar"}
    real_time = time.time
    fake_now = time.mktime((2026, 11, 10, 12, 0, 0, 0, 0, -1))
    time.time = lambda: fake_now
    lines = [L("11-10 11:59:00.100", "plugin.foo", "boom one")]
    p._parse_log(lines, ids)
    check("log: first parse adds issue", sum(i["count"] for i in p.issues.values()) == 1)
    p._parse_log(lines, ids)
    check("log: re-parse same lines adds nothing", sum(i["count"] for i in p.issues.values()) == 1)
    lines2 = lines + [L("11-10 11:59:00.100", "plugin.foo", "boom two same ms")]
    p._parse_log(lines2, ids)
    check("log: new line with the same millisecond is not lost", sum(i["count"] for i in p.issues.values()) == 2, p.issues.keys())
    p._parse_log(lines2, ids)
    check("log: still no duplicates", sum(i["count"] for i in p.issues.values()) == 2)

    # Новый год
    fake_now = time.mktime((2027, 1, 1, 0, 1, 0, 0, 0, -1))
    p = mk(new); p._parse_log([L("12-31 23:59:50.000", "plugin.foo", "old year")], ids)
    c0 = sum(i["count"] for i in p.issues.values())
    p._parse_log([L("12-31 23:59:50.000", "plugin.foo", "old year"), L("01-01 00:00:20.000", "plugin.bar", "new year err")], ids)
    check("log NEW: line after New Year is parsed", sum(i["count"] for i in p.issues.values()) == c0 + 1, [i["plugin"] for i in p.issues.values()])

    # часы назад
    fake_now = time.mktime((2026, 11, 10, 12, 0, 0, 0, 0, -1))
    p = mk(new); p._parse_log([L("11-10 12:00:00.000", "plugin.foo", "a")], ids)
    n0 = sum(i["count"] for i in p.issues.values())
    p._parse_log([L("11-10 10:00:00.000", "plugin.bar", "after clock set back")], ids)
    check("log: clock jumped back -> cursor reset, batch skipped", sum(i["count"] for i in p.issues.values()) == n0)
    p._parse_log([L("11-10 10:00:00.000", "plugin.bar", "after clock set back"), L("11-10 10:00:05.000", "plugin.bar", "next")], ids)
    check("log: parsing continues after reset", any(i["plugin"] == "bar" for i in p.issues.values()))

    # крэш и питон-трейс
    p = mk(new)
    p._parse_log([L("11-10 11:00:00.000", "AndroidRuntime", "FATAL EXCEPTION: main", pid=7, tid=7),
                  L("11-10 11:00:00.001", "AndroidRuntime", "java.lang.NullPointerException: x", pid=7, tid=7),
                  L("11-10 11:00:00.002", "AndroidRuntime", "\tat com.foo.plugin.Thing.run(Thing.java:1)", pid=7, tid=7)], {"foo"})
    check("log: crash block still parsed", any(i["kind"] == "crash" for i in p.issues.values()), [(i["kind"], i["plugin"]) for i in p.issues.values()])

    # ---------- 5. карта файл -> id, слабые совпадения
    import os, tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "445a903a-my_tool_v1.plugin"), "w").write('__id__ = "my_tool"\n')
    open(os.path.join(d, "plain.plugin"), "w").write("# no id\n")
    new.get_plugins_dir = lambda: d
    p = mk(new); p._plugins_info = lambda: []
    ids2 = p._plugin_ids()
    check("ids: stem replaced by real __id__", "my_tool" in ids2 and "445a903a-my_tool_v1" not in ids2 and "plain" in ids2, sorted(ids2))
    res = new.StallDoctorPlugin._plugins_from_paths('File "/x/plugins/445a903a-my_tool_v1.plugin", line 3', ids2)
    check("paths: stem mapped to id", res == ["my_tool"], res)
    wk = set()
    m = new.StallDoctorPlugin._match_plugins(["com.mytoolkit.network"], {"my_toolkit_x"}, wk)
    wk2 = set(); m2 = new.StallDoctorPlugin._match_plugins(["com.foobar.api"], {"foobar"}, wk2)
    check("match: exact id segment is strong", m2 == ["foobar"] and not wk2, (m2, wk2))
    wk3 = set(); m3 = new.StallDoctorPlugin._match_plugins(["com.example.weather.api"], {"weather_widget"}, wk3)
    check("match: token-only match is flagged weak", m3 == ["weather_widget"] and wk3 == {"weather_widget"}, (m3, wk3))

    # ---------- 3/4. _tick: прогресс и склейка эпизодов
    def mk_tick(mod):
        p = mod.StallDoctorPlugin()
        p.probes = {n: mod.Probe(n) for n in ("ui","plugins","stage","global","ping")}
        p.history = collections.deque(maxlen=120); p.cond_since = {}; p.loaded_at = 0.0
        p.state_names = dict(mod.DEFAULT_STATE_NAMES); p.skip_until = 0.0
        p.episode = False; p.healthy_ticks = 0; p.suspicious = False
        p.prog_last = None; p.prog_at = 0.0; p.ep_prev = None; p.ep_prev_end = 0.0; p.ep_cur = None; p.last_report_t = 0.0
        p._rlang = None; p.cur = {"t": 0, "conn": 3, "net": True, "gd": False, "paused": False, "prog": None}
        p.log = []; p.reports = []; p.bumped = 0; p.starts = 0
        p._acc = lambda: 0; p._fire_probes = lambda a, n: None
        p._sample = lambda a, n: dict(p.cur, t=n)
        p._part = lambda *a, **k: None
        p.ev = lambda t, defer=False: p.log.append(t)
        p._bump = lambda k: setattr(p, "bumped", p.bumped + 1)
        def es(now, reason, s): p.starts += 1; p.ep_cur = {"t0": now}
        p._episode_start = es
        p._episode_update = lambda t0, **kw: p.log.append(("upd", kw))
        p.make_report = lambda reason, manual: p.reports.append(reason)
        mod.threading.Thread = lambda target=None, args=(), name=None, daemon=None: types.SimpleNamespace(start=lambda: target(*args))
        return p
    realThread = threading.Thread

    # 3a: Updating 60 с, pts двигается -> не зависание
    p = mk_tick(new); p.loaded_at = -1000.0
    for k in range(14):
        now = 1000.0 + k * 5
        p.cur = dict(conn=3 if False else 5, net=True, gd=False, paused=False, prog=(("lastPts", k),))
        p._sample = (lambda c: (lambda a, n: dict(c, t=n)))(p.cur)
        # имитируем то, что делает настоящий _sample с прогрессом
        if p.cur["prog"] != p.prog_last: p.prog_last = p.cur["prog"]; p.prog_at = now
        p._tick(now)
    check("tick: long Updating with advancing pts is NOT a freeze", p.starts == 0 and not p.episode)
    # 3b: тот же Updating, pts стоит
    p = mk_tick(new); p.loaded_at = -1000.0; p.prog_last = (("lastPts", 1),); p.prog_at = 1000.0
    for k in range(14):
        now = 1000.0 + k * 5
        c = dict(conn=5, net=True, gd=False, paused=False, prog=(("lastPts", 1),))
        p._sample = (lambda c: (lambda a, n: dict(c, t=n)))(c)
        p._tick(now)
    check("tick: Updating with frozen pts IS a freeze", p.starts == 1 and p.episode, p.log[-3:])
    # 3c: нет данных о pts -> как раньше по времени
    p = mk_tick(new); p.loaded_at = -1000.0
    for k in range(14):
        now = 1000.0 + k * 5
        c = dict(conn=5, net=True, gd=False, paused=False, prog=None)
        p._sample = (lambda c: (lambda a, n: dict(c, t=n)))(c)
        p._tick(now)
    check("tick: no pts data falls back to time-based rule", p.starts == 1)
    # 4: склейка эпизодов и пауза отчётов
    t = 1100.0
    def run(p, conn, secs, start):
        now = start
        for _ in range(int(secs // 5)):
            c = dict(conn=conn, net=True, gd=False, paused=False, prog=None)
            p._sample = (lambda c: (lambda a, n: dict(c, t=n)))(c)
            p._tick(now); now += 5
        return now
    p = mk_tick(new); p.loaded_at = -1000.0
    t = run(p, 5, 60, 1000.0)           # эпизод
    t = run(p, 3, 20, t)                # здоров 4 тика -> закрыт
    check("episode closes after healthy ticks", not p.episode and p.ep_prev is not None)
    t = run(p, 5, 60, t)                # снова через ~20 с
    check("episode merge: no second episode record / counter", p.starts == 1 and p.bumped == 1, (p.starts, p.bumped))
    check("episode merge: second report throttled", len(p.reports) == 1, p.reports)
    check("episode merge: reopened in storage", any(isinstance(x, tuple) and x[0] == "upd" and x[1].get("open") is True for x in p.log))
    p2 = mk_tick(new); p2.loaded_at = -1000.0
    t = run(p2, 5, 60, 1000.0); t = run(p2, 3, 20, t); t += 400
    t = run(p2, 5, 60, t)
    check("episode: far apart -> new episode", p2.starts == 2 and p2.bumped == 2, (p2.starts, p2.bumped))

    # ---------- 6. swallow
    new._SWALLOWED.clear()
    try:
        raise ValueError("x")
    except Exception as _e:
        new._swallow(_e)
    check("swallow: counted with location", len(new._SWALLOWED) == 1 and list(new._SWALLOWED.values())[0][0] == 1, new._SWALLOWED)
    pp = mk(new); pp.cpu_hist = collections.deque(); pp.base_dir = d; pp.t = lambda key, **kw: f"{key}{kw}"
    pp._rlang = None
    out = pp._self_cost_lines()
    check("selfcost lists swallowed errors", any("sc_swallow" in x for x in out), out[-3:])



def test_core():
    real_time, real_thread = time.time, threading.Thread
    try:
        run()
    finally:
        time.time = real_time
        threading.Thread = real_thread
    assert not check.fails, check.fails
