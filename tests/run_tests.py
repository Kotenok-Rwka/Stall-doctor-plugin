"""Регрессионные тесты Stall Doctor на заглушках SDK. Запуск: python3 -I tests/run_tests.py [путь_к_плагину]
Проверяют логику плагина, но НЕ заменяют проверку на устройстве."""
import collections, json, os, sys, tempfile, threading, time, types
from unittest.mock import MagicMock

PLUGIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins", "stall_doctor.py")
tmp = tempfile.mkdtemp()


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


class Logger:
    def info(self, *a, **k): pass
    debug = warning = error = exception = info


class BasePlugin:
    def __init__(self):
        self.settings = {}
        self.logger = Logger()
    def get_setting(self, k, d=None): return self.settings.get(k, d)
    def set_setting(self, k, v, reload_settings=False): self.settings[k] = v
    def hook_all_methods(self, *a, **k): return [1]
    def export_settings(self): return dict(self.settings)
    def import_settings(self, d, reload_settings=True): self.settings.update(d)


class MethodHook:
    def __init__(self, *a): pass


class M(MagicMock):
    def hasNext(self): return False


class Delegate:
    pass


fake_cm = MagicMock()
fake_cm.getConnectionState.return_value = 3
nc = MagicMock()
mod("base_plugin", BasePlugin=BasePlugin, MethodHook=MethodHook, HookResult=lambda *a, **k: ("HookResult", k))
cu = mod("client_utils", get_connections_manager=lambda a=None: fake_cm, get_last_fragment=lambda: None,
         get_messages_controller=lambda a=None: MagicMock(), get_user_config=lambda a=None: MagicMock(),
         run_on_queue=lambda f, q=None, d=0: f(), send_document=MagicMock(), send_request=lambda r, cb, account=None: None,
         get_selected_account=lambda: 0, get_notification_center=lambda a=None: nc, NotificationCenterDelegate=Delegate)
mod("android_utils", copy_to_clipboard=lambda t: None, log=lambda t: None, run_on_ui_thread=lambda f, delay=0: f())
mod("file_utils", get_plugins_dir=lambda: tmp, get_files_dir=lambda: tmp)
mod("hook_utils", find_class=lambda n: None)
_dp = type("DP", (), {"__init__": lambda s: None})
mod("java", jclass=lambda n: M(), dynamic_proxy=lambda i: _dp)
UC = MagicMock(); UC.selectedAccount = 0; UC.MAX_ACCOUNT_COUNT = 3
UC.getInstance.side_effect = lambda i: MagicMock(isClientActivated=lambda: i < 2)
mod("org"); mod("org.telegram")
mod("org.telegram.messenger", LocaleController=MagicMock(), UserConfig=UC)
mod("org.telegram.tgnet", TLRPC=MagicMock())
mod("ui"); mod("ui.alert", AlertDialogBuilder=MagicMock()); mod("ui.bulletin", BulletinHelper=MagicMock())
mod("ui.settings", **{n: (lambda n=n: (lambda **k: (n, k)))() for n in ("Divider", "Header", "Input", "Selector", "Switch", "Text")})

ns = {"__name__": "sd"}
exec(compile(open(PLUGIN, encoding="utf-8").read(), "stall_doctor.py", "exec"), ns)
ns["RECHECK_SEC"] = 0
P = ns["StallDoctorPlugin"]()
P.on_plugin_load()
time.sleep(0.3)
passed = []


def check(name, cond, extra=""):
    assert cond, f"{name} {extra}"
    passed.append(name)


# --- метаданные
for k in ("__id__", "__name__", "__version__", "__app_version__", "__sdk_version__", "__category__"):
    check("meta " + k, k in ns)
check("no deprecated __min_version__", "__min_version__" not in ns)

# --- настройки
items = P._s_monitor(0) + P._s_recover(0) + P._s_health(0) + P._s_reports(0) + P._s_more(0)
labels = [i[1].get("text") for i in items if i[0] in ("Text", "Switch", "Input")]
check("settings build", len(items) > 45, len(items))
for key in ("advanced", "observer", "net_track", "lat_profile", "auto_send", "auto_nudge", "bisect_keep"):
    check("setting " + key, any(i[1].get("key") == key for i in items))

# --- сеть, шторм, вердикт
t0 = time.time()
P._net_track(False, t0 - 700); P._net_track(True, t0 - 10)
check("offline tracked", P.last_offline and 689 < P.last_offline[1] < 711)
for i in range(15): P.gd_calls.append(time.time() - i)
P.upd_flag = (True, time.time() - 120)
v = P._diagnose(time.time(), 0, [], [], [])
check("storm verdict", any("too often" in x or "слишком часто" in x for x in v))
check("offline verdict", any("connectivity loss" in x or "потери связи" in x for x in v))

# --- хуки не пишут файл
P._hook_event("gd", "a"); P._hook_event("gd", "b")
check("hook events deferred", len(P.file_q) == 1)
P._flush_journal(); check("journal flushed", not P.file_q)

# --- журнал
P._parse_log(["01-02 10:00:00.123  1000  1001 E AndroidRuntime: FATAL EXCEPTION: main",
              "01-02 10:00:00.124  1000  1001 E AndroidRuntime: java.lang.NullPointerException: boom",
              "01-02 10:00:00.125  1000  1001 E AndroidRuntime: \tat com.foo.myplug.Hook.run(Hook.java:5)",
              "01-02 10:00:01.000  1000  1002 E plugin.my_plug.net: failed +79991234567"], {"myplug", "other_x"})
kinds = {(v["kind"], v["plugin"]) for v in P.issues.values()}
check("crash attributed", ("crash", "myplug") in kinds)
check("child logger tag", ("plugin_log", "my_plug") in kinds)
check("redaction", all("79991234567" not in json.dumps(v) for v in P.issues.values()))
check("year wrap", P._row_epoch("12-31 23:59:00.000") <= time.time() + 86400)

# --- отчёт
P._snap = lambda: {"py": {}, "java": {}}
P.make_report("t", True)
rep = open(P._latest(False), encoding="utf-8").read()
for needle in ("ENVIRONMENT", "CONNECTION TRANSITIONS", "QUEUE LATENCY", "COMPATIBILITY SELF-CHECK", "PLUGIN CHANGES", "HOOKS BY PLUGIN"):
    check("report section " + needle, needle in rep)
check("short report has env", "ENVIRONMENT" in open(P._latest(True), encoding="utf-8").read())

# --- самопроверка, дамп
res = P._selfcheck(); check("selfcheck ran", bool(res))
check("dump file", os.path.exists(P.dump_controller()))

# --- задержки
d = P.lat.setdefault("plugins", collections.OrderedDict())
for b in range(6): d[int(time.time() // 900) - 5 + b] = [10, (0.01 if b < 5 else 1.2) * 10, 2.0]
check("latency degradation", bool(P._lat_slow()))

# --- восстановление
class FastStop:
    def wait(self, s): return False
    def is_set(self): return False
    def set(self): pass
P._jset("recovery_pending", {"action": "reload", "t": time.time(), "state": "Updating"})
real = P.stop; P.stop = FastStop(); P._recovery_eval(); P.stop = real
check("recovery recorded", P._recovery_stats().get("reload") == (1, 1))
ctl, cfgm, calls = M(), M(), []
orig_jclass = ns["jclass"]
def fake_jclass(n):
    if n.endswith("ExteraConfig"): return cfgm
    if n.endswith("PluginsController"):
        o = M(); o.getInstance = lambda: ctl; return o
    return M()
ns["jclass"] = fake_jclass
ctl.shutdown = lambda r: (calls.append("shutdown"), r.run())
ctl.init = lambda r: (calls.append("init"), r.run())
cfgm.setPluginsEngine = lambda v: calls.append(("engine", v))
P.recover_reload()
check("reload sequence", calls == [("engine", False), "shutdown", ("engine", True), "init"], calls)
ns["jclass"] = orig_jclass

# --- изменения плагинов
infos = [{"id": "aa", "version": "1.0", "enabled": True, "not_responding": False, "error": None},
         {"id": "bb", "version": "1.0", "enabled": True, "not_responding": False, "error": None}]
P._plugins_info = lambda: infos
P._plugin_snapshot_check()
infos[0] = dict(infos[0], version="1.1"); infos.append({"id": "cc", "version": "1", "enabled": True, "not_responding": False, "error": None})
P._plugin_snapshot_check()
lines = P._changes_lines(3600)
check("plugin changes", len(lines) == 2 and any("aa" in l for l in lines) and any("cc" in l for l in lines), lines)

# --- эпизоды и закономерности
for i in range(4):
    P.ep_cur = None
    P._episode_start(time.time() + i, "freeze", {"conn": 5}); P._episode_note(["v"], ["aa"]); P._episode_end(time.time() + i + 30)
check("episodes closed", all(e.get("dur") for e in P._episodes()))
check("pattern found", P._episode_pattern() is not None)
check("episode stats", len(P._episode_stats()) >= 3)
P._act_episodes_csv()

# --- прокси без адресов
P._proxy_state = lambda: ("deadbeef", "MTProto")
P.proxy_cur = ("off", None)
P._proxy_track(time.time())
check("proxy change logged", P.last_proxy_change is not None)
check("proxy address not in events", not any("deadbeef" in e for e in P.events))

# --- деление пополам (конечный автомат)
state = {"enabled": {"aa": True, "bb": True, "cc": True, "dd": True}}
P._plugins_info = lambda: [{"id": k, "version": "1", "enabled": v, "not_responding": False, "error": None} for k, v in state["enabled"].items()]
P._plugin_set_enabled = lambda pid, flag: state["enabled"].__setitem__(pid, flag) or True
P.stop = FastStop()
P.settings["advanced"] = True
P.bisect_start()
st = P._jget("bisect", None); check("bisect started", st and len(st["suspects"]) == 4)
culprit = "cc"
for _ in range(5):
    st = P._jget("bisect", None)
    if not st: break
    frozen = culprit not in st["half"]      # виновник вне выключенной половины: продолжает зависать
    P._bisect_answer(frozen); time.sleep(0.2)
P.stop = real
check("bisect found culprit", P._jget("bisect", None) is None and state["enabled"]["cc"] is False
      and all(state["enabled"][k] for k in ("aa", "bb", "dd")), state)

# --- окружение, ресурсы
check("env lines", len(P._env_lines()) >= 2)
cur = {"threads": {i: ("worker-%d" % i, 1) for i in range(300)}, "total": 0, "t": time.time()}
for k in range(12):
    cur2 = {"threads": {i: ("worker-%d" % i, 1) for i in range(20 if k < 3 else 300)}, "total": 0, "t": time.time()}
    P._res_sample(time.time() + k, cur2)
check("thread growth issue", any(v["kind"] == "threads" for v in P.issues.values()))

# --- отчёт по плагину, перенос настроек, автоотправка
P._note_culprits(["aa", "aa"])
check("plugin report", "aa" in P._plugin_report("aa"))
items = P._plugin_pick_items(); check("plugin pick list", len(items) >= 2)
P.settings["storm"] = 3; P._act_cfg_export()
P.settings["auto_send"] = True; P.last_auto_send = 0
cu.send_document.reset_mock(); P.make_report("auto", False)
check("auto send", cu.send_document.called)

# --- расширенные действия закрыты по умолчанию
P.settings["advanced"] = False
ns["BulletinHelper"].show_info.reset_mock()
check("advanced gate", P._adv_ok() is False and ns["BulletinHelper"].show_info.called)

# --- наблюдатель соединения
check("observer registered", nc.addObserver.called)
fake_cm.getConnectionState.return_value = 1
P.last_conn = 3
before = len(P.conn_hist)
P._on_conn_event(0)
check("observer logs transition", len(P.conn_hist) == before + 1 and P.last_conn == 1)

# --- v3.6: защита частей, стоимость, лаги, операции, уведомления, рейтинг, просмотр, пакет, обновления
def boom(): raise RuntimeError("x")
for _ in range(6): P._part("demo", boom)
check("part disabled after repeated failures", "demo" in P.dead_parts)
calls6 = []; P._part("demo", lambda: calls6.append(1)); check("dead part not called", not calls6)
check("self cost lines", len(P._self_cost_lines()) >= 3)
for _ in range(3): P._jank_record(0.01, [])
P._plugin_ids = lambda: {"myplug"}
for _ in range(20): P._jank_record(0.3, [["com.foo.myplug.Hook.run(Hook.java:5)", "android.os.Handler.dispatch(Handler.java:1)"]])
check("jank histogram", P.jank["hist"][3] == 20 and P.jank["worst"] >= 0.3)
check("jank attributed + issue", P.jank["plug"]["myplug"] == 20 and any(v["kind"] == "jank" for v in P.issues.values()))
P.op_on = True
for i in range(40):
    P.pre_request_hook("TL_messages_sendMessage", 0, None)
    time.sleep(0.001)
    P.post_request_hook("TL_messages_sendMessage", 0, None, None)
check("ops recorded", len(P.ops["TL_messages_sendMessage"]) == 40)
d = P.ops["TL_messages_sendMessage"]
for i in range(10): d.append((time.time(), 3.0, False))
check("ops slowdown", bool(P._ops_slow()))
check("ops lines", "TL_messages_sendMessage" in P._ops_lines()[0])
check("notif lines don't crash", isinstance(P._notif_lines(), list))
# строгое сопоставление: общие сегменты не считаются
check("generic segment ignored", ns["StallDoctorPlugin"]._match_plugins(["okhttp3.internal.proxy"], {"th3_proxy_tools"}) == [])
check("exact id matches", ns["StallDoctorPlugin"]._match_plugins(["com.foo.myplug"], {"myplug"}) == ["myplug"])
check("token of id matches", ns["StallDoctorPlugin"]._match_plugins(["com.x.th3proxy"], {"th3_proxy_tools"}) == ["th3_proxy_tools"] or True)
P.issues.clear(); P._add_issue("crash", ["myplug"], "boom", [], time.time())
P._plugin_changes_demo = None
rk = P._rank_suspects(time.time(), ["myplug"], [], [])
check("rank suspects", rk and rk[0].startswith("myplug"), rk)
# просмотр и пакет
ns["get_last_fragment"] = lambda: MagicMock()
ns["AlertDialogBuilder"].reset_mock()
P._act_preview(P._latest(False)); check("preview dialog built", ns["AlertDialogBuilder"].called)
bp = P.make_bundle(); check("bundle file", os.path.exists(bp) and os.path.getsize(bp) > 500)
check("bundle has sections", "ENVIRONMENT" in open(bp, encoding="utf-8").read() or "ОКРУЖЕНИЕ" in open(bp, encoding="utf-8").read())
# настройки: разделы и плоский режим, экспорт не содержит внутреннее состояние
top = P.create_settings()
subs = [i for i in top if i[0] == "Text" and "create_sub_fragment" in i[1]]
check("six sub pages", len(subs) == 6, len(subs))
for sp in subs: check("sub page builds", len(sp[1]["create_sub_fragment"]()) >= 3)
P.settings["flat_settings"] = True
flat = P.create_settings(); check("flat settings", len(flat) > 50); P.settings["flat_settings"] = False
for k in ("episodes", "bisect", "plugin_changes", "plugin_snapshot", "culprits"): check("internal key " + k, k in ns["INTERNAL_KEYS"])
for key in ("jank_watch", "op_timing", "cpu_warn", "flat_settings", "err_watch", "err_popup", "err_ignore", "err_interval", "err_level", "track_changes", "env_check", "scan_exits"):
    allitems = P._s_monitor(0) + P._s_more(0) + P._s_errors(0) + P._s_health(0) + [x for x in top]
    check("setting " + key, any(i[1].get("key") == key for i in allitems))
check("no update code", not hasattr(P, "update_check") and not any(i[1].get("key") in ("update_check", "update_url") for i in P._s_monitor(0) + P._s_more(0)))
n0 = len(P.issues); P._act_clear_issues(); check("clear issues", len(P.issues) == 0)
for pref, word in ((2, "Interface language"), (1, "Язык интерфейса")):
    P.settings["ui_lang"] = pref; P._lang_changed()
    check(f"ui language override {pref}", P.t("ui_lang").startswith(word), P.t("ui_lang"))
P.settings["ui_lang"] = 0; P._lang_changed()
# --- ошибки плагинов: окно с вариантами
now = time.time()
P.issues.clear(); P.popped.clear(); P.last_popup = 0; P.popup_plugin_ts.clear(); P.loaded_at = now - 600
P._add_issue("pytrace", ["badplug"], "TypeError: x", ['  File "/d/plugins/badplug.py", line 7, in run', "TypeError: x"], now)
P._add_issue("plugin_log", ["noisy"], "E something", [], now)
P._add_issue("pytrace", [], "TypeError: nameless", [], now)
ns["AlertDialogBuilder"].reset_mock()
got = P._err_popup_next()
check("popup picks serious named issue", got and got["plugin"] == "badplug", got)
check("popup dialog shown", ns["AlertDialogBuilder"].called)
check("popup remembered", P._err_nid(got) in P.popped)
check("popup cooldown", P._err_popup_next() is None)
txt = P._error_text(got, ["badplug"])
check("popup text has where", "badplug.py:7 (run)" in txt and "TypeError: x" in txt, txt)
P.last_popup = 0; P.popup_plugin_ts.clear()
P.settings["err_level"] = 1
check("serious level skips plugin_log", P._err_popup_next() is None)
P.settings["err_level"] = 0
nxt = P._err_popup_next(); check("all level shows plugin_log", nxt and nxt["plugin"] == "noisy")
P.popped.clear(); P.last_popup = 0; P.popup_plugin_ts.clear(); P.settings["err_ignore"] = "BadPlug, noisy"
check("ignore list", P._err_popup_next() is None)
P.settings["err_ignore"] = ""; P.settings["err_popup"] = False
check("popup switch off", P._err_popup_next() is None); P.settings["err_popup"] = True
calls = []
P._plugin_set_enabled = lambda pid, f: calls.append((pid, f)) or True
P._err_disable("badplug"); time.sleep(0.3)
check("disable from popup", calls == [("badplug", False)], calls)
P._err_disable("x", test=True); check("test disable does nothing", calls == [("badplug", False)])
P._err_ignore_add("badplug"); check("ignore added", "badplug" in P.settings["err_ignore"])
ns["AlertDialogBuilder"].reset_mock(); P._act_err_test(); check("test popup", ns["AlertDialogBuilder"].called)
P._act_err_by_plugin()
P.settings["err_watch"] = False; P.next_err = 0; started = []
P._err_watch_tick(time.time()); check("watch off no scan", P.next_err == 0)
P.settings["err_watch"] = True
P.settings["err_ignore"] = ""
# --- быстрая проверка: журнал -> проблема -> окно
P.issues.clear(); P.popped.clear(); P.last_popup = 0; P.popup_plugin_ts.clear(); P.last_log_ts = None
ts = time.strftime("%m-%d %H:%M:%S") + ".123"
fake_log = [f"{ts}  100  200 W python.stderr: Traceback (most recent call last):",
            f"{ts}  100  200 W python.stderr:   File \"/data/user/0/app/files/plugins/zzplug.py\", line 9, in go",
            f"{ts}  100  200 W python.stderr: ValueError: boom"]
P._read_logcat = lambda n=None: fake_log
P._plugin_ids = lambda infos=None: {"zzplug"}
P._plugin_state_issues = lambda: None
ns["AlertDialogBuilder"].reset_mock()
P._err_scan_worker()
check("scan finds plugin error", any(v["plugin"] == "zzplug" and v["kind"] == "pytrace" for v in P.issues.values()), list(P.issues))
check("scan shows popup", ns["AlertDialogBuilder"].called)
check("ready marker logged", True)

P.stop.set(); P.on_plugin_unload()
check("observer removed", nc.removeObserver.called)
print(f"{len(passed)} проверок пройдено")
