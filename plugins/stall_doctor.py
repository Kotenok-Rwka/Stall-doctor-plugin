import collections
import hashlib
import json
import os
import re
import sys
import threading
import time
import traceback

import client_utils as cu
from android_utils import copy_to_clipboard, log as android_log, run_on_ui_thread
from base_plugin import BasePlugin, HookResult, MethodHook
from client_utils import get_connections_manager, get_last_fragment, get_messages_controller, get_user_config, run_on_queue, send_document, send_request
from file_utils import get_plugins_dir
from hook_utils import find_class
from java import jclass
from org.telegram.messenger import LocaleController, UserConfig
from org.telegram.tgnet import TLRPC
from ui.alert import AlertDialogBuilder
from ui.bulletin import BulletinHelper
from ui.settings import Divider, Header, Input, Selector, Switch, Text

try:
    from file_utils import get_files_dir
except Exception:
    get_files_dir = None

__id__ = "stall_doctor"
__name__ = "Stall Doctor"
__description__ = (
    "Находит причину зависаний и сбоев Telegram и называет плагин-виновник.\n\n"
    "**Что умеет**\n"
    "• следит за интерфейсом, очередями и связью с сервером\n"
    "• при ошибке другого плагина показывает окно: что случилось и что можно сделать\n"
    "• разбирает журнал: краши, исключения Python, ANR, падения прошлых запусков\n"
    "• по каждой найденной проблеме простыми словами пишет, что случилось, что это значит и что делать\n"
    "• собирает полный отчёт для баг-репорта: его можно скопировать или отправить в Избранное\n\n"
    "**Приватность**\n"
    "Сообщения, номера и адреса прокси в отчёт не попадают. Наружу ничего не отправляется.\n\n"
    "**Безопасность**\n"
    "Рискованные действия (перезагрузка плагинов, деление списка пополам) работают только по вашей кнопке и включаются отдельной настройкой."
)
__author__ = "@Kotenok_Rwka, Claude"
__version__ = "3.9.0"
__app_version__ = ">=12.10.6"
__sdk_version__ = ">=1.4.5.0"
__icon__ = "OliverEmoji/21"
__category__ = ["tools"]

TICK = 5                  # период проверки, сек
PROBE_LOST = 90           # проба без ответа дольше этого считается потерянной: шлём новую, не ждём вечно
PROGRESS_KEYS = ("gettingDifference", "conn:Updating")   # «зависание» только если при этом нет прогресса по pts/seq
EP_MERGE_SEC = 150        # новая заминка сразу после конца прошлой считается продолжением того же эпизода
REPORT_GAP = 120          # автоматические отчёты не чаще, чем раз в столько секунд
LOG_CLOCK_BACK = 300      # журнал «ушёл в прошлое» больше чем на столько секунд: часы переводили, курсор сбрасываем
PROBE_LIMIT = 15          # очередь / UI «не отвечают» после стольких секунд
PING_LIMIT = 25           # запрос к серверу «не отвечает» после стольких секунд
PING_HEALTHY_EVERY = 30
PING_SUSPECT_EVERY = 5
RECHECK_SEC = 15          # пауза между двумя снимками потоков
GRACE_SEC = 45            # после запуска плагина мягкие условия не считаются
SLEEP_LAG = 15            # опоздание сторожа, после которого считаем, что телефон спал
NOTIFY_COOLDOWN = 300
ERR_LOG_LINES = 1500        # строк журнала при быстрой проверке ошибок
ERR_INTERVALS = [30, 60, 180, 600]
POPUP_COOLDOWN = 90         # между двумя окнами, сек
POPUP_PLUGIN_COOLDOWN = 600 # для одного и того же плагина, сек
ERR_RECENT = 1800
ISSUE_TTL = [86400, 3 * 86400, 7 * 86400, 0]   # сколько хранить проблему; 0 = без ограничения
ERR_PRIO = {"crash": 0, "ui": 1, "exit": 1, "pytrace": 2, "plugin_state": 3, "hook": 4, "plugin_log": 5}
ERR_SERIOUS = ("crash", "ui", "exit", "pytrace", "plugin_state")
THRESHOLDS = [15, 30, 60, 120]
HIST_MAX = 120
MAX_FRAMES = 25
REPORT_KEEP = 5
MAX_STACK_CHARS = 40000
HEALTH_FIRST = 25         # первая проверка журнала через N секунд после запуска
HEALTH_EVERY = 600        # потом раз в 10 минут
LOG_LINES = 4000
UI_BLOCK = 4              # UI-поток не отвечал столько секунд: снимаем стек
NOTIFY_ISSUE_MIN = 10
NOTIFY_RECENT = 1800      # уведомляем только о проблемах за последние 30 минут
ATTR_KINDS = ("crash", "pytrace", "ui", "plugin_log", "hook")   # проблемы, у которых виновного плагина ждут по стеку
EXC_HINTS = [   # (регулярка, ключ строки): расшифровка частых исключений простыми словами
    (re.compile(r"ZeroDivision|divide by zero|/ by zero", re.I), "xh_zero"),
    (re.compile(r"NullPointer|NoneType|is null|null object", re.I), "xh_null"),
    (re.compile(r"OutOfMemory|MemoryError"), "xh_oom"),
    (re.compile(r"StackOverflow|RecursionError|maximum recursion", re.I), "xh_stack"),
    (re.compile(r"ConcurrentModification|changed size during iteration"), "xh_conc"),
    (re.compile(r"NoSuchMethod|NoSuchField|ClassNotFound|NoClassDefFound|AbstractMethodError|IncompatibleClassChange|ImportError|ModuleNotFound|AttributeError|has no attribute"), "xh_compat"),
    (re.compile(r"IndexOutOfBounds|IndexError|KeyError"), "xh_index"),
    (re.compile(r"ClassCastException|TypeError|ValueError|NumberFormat"), "xh_type"),
    (re.compile(r"Timeout|timed out", re.I), "xh_timeout"),
    (re.compile(r"SecurityException|PermissionError"), "xh_perm"),
]
EXIT_NAMES = {3: "LOW_MEMORY", 4: "CRASH", 5: "CRASH_NATIVE", 6: "ANR", 7: "INITIALIZATION_FAILURE", 9: "EXCESSIVE_RESOURCE_USAGE"}
_SWALLOWED = {}
_STEM_CACHE = [0.0, {}]
STEM_MAP = {}
ID_RE = re.compile(r"""__id__\s*=\s*["']([^"']+)["']""")


def _swallow(e=None):
    """Считает ошибки, которые раньше глотались молча: место (функция:строка) -> сколько раз и последний текст."""
    try:
        tb = e.__traceback__ if e is not None else sys.exc_info()[2]
        if tb is None:
            return
        key = f"{tb.tb_frame.f_code.co_name}:{tb.tb_lineno}"
        row = _SWALLOWED.get(key)
        if row is None:
            if len(_SWALLOWED) >= 200:
                return
            row = _SWALLOWED[key] = [0, "", 0.0]
        row[0] += 1
        row[1] = f"{type(e).__name__}: {e}"[:120] if e is not None else ""
        row[2] = time.time()
    except Exception:
        pass


LOG_RE = re.compile(r"^(\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(.+?)\s*: ?(.*)$")
PLUGIN_PATH_RE = re.compile(r"plugins/([A-Za-z0-9_\-]+)\.(?:py|pyc|plugin)")

REL_RE = re.compile(r"plugin|python|chaquopy|exteragram|MessagesController|ConnectionsManager|NotificationCenter", re.I)
QUEUE_NAME_RE = re.compile(r"queue|main|stage|plugin|network|dispatch", re.I)
JANK_MS = 150
OP_HOOKS = ("TL_messages_send", "TL_messages_getHistory", "TL_messages_getDialogs")
FRAMEWORK_PREFIXES = ("android.", "java.", "javax.", "dalvik.", "com.android.", "libcore.", "jdk.", "sun.")
BUCKETS = {5: "EXEMPTED", 10: "ACTIVE", 20: "WORKING_SET", 30: "FREQUENT", 40: "RARE", 45: "RESTRICTED", 50: "NEVER"}
MARK_RE = re.compile(r"<url>|<num>|@<user>")
GENERIC_SEGS = {"internal", "common", "utils", "util", "core", "base", "client", "server", "android", "proxy", "telegram", "plugin",
                "plugins", "tools", "helper", "manager", "network", "media", "data", "impl", "model", "models", "okhttp3", "kotlin"}
HOOKISH_RE = re.compile(r"hook|filter|listener|handler|callback|registry", re.I)
UPD_RE = re.compile(r"TL_update|getDifference|processUpdates", re.I)
INTERNAL_KEYS = {"notified_keys", "ui_refresh", "stat_episodes", "stat_rescued", "recovery_pending", "recovery_log", "culprits",
                 "plugin_snapshot", "plugin_changes", "episodes", "bisect", "popped_keys", "cleared_at", "app_ver", "app_change"}
MC_FIELDS_RE = r"difference|updatesQueue|updatesStartWait|updatingState|lastPts|lastQts|lastSeq|lastDate|loadingDialogs|dialogsLoadedTill|getDiff"
CM_FIELDS_RE = r"updating|connectionState|appPaused|lastKnown|currentNetwork|isNetwork|proxy"
DEFAULT_STATE_NAMES = {1: "Connecting", 2: "WaitingForNetwork", 3: "Connected", 4: "ConnectingToProxy", 5: "Updating"}
SAFE_PREFIXES = ("org.telegram.", "android.", "androidx.", "java.", "javax.", "jdk.", "kotlin.", "kotlinx.", "com.android.",
                 "com.chaquo.", "com.exteragram.", "de.robv.android.xposed.", "dalvik.", "libcore.", "sun.", "com.google.",
                 "org.lsposed.", "org.json", "LSPHooker_", "j$.", "org.chromium.", "WV.", "com.android.webview.", "org.webrtc.", "org.conscrypt.")
BENIGN_THREAD_RE = re.compile(r"^(CleanupReference|ReferenceQueueDaemon|FinalizerDaemon|FinalizerWatchdogDaemon|HeapTaskDaemon|Signal Catcher|binder:|"
                              r"RenderThread|hwuiTask|Jit thread pool|DefaultDispatcher-worker|OkHttp|Chrome_|PyObject releaser|Timer-|"
                              r"queued-work-looper|AsyncTask|ConnectivityThread|Thread-\d+ \(.*\)$)")
STORM_VALUES = [0, 8, 12, 20]            # вызовов getDifference в минуту; 0 = не искать
OFFLINE_VALUES = [300, 600, 1800, 3600]  # секунды потери сети, после которых она попадает в вердикт
CPU_EVERY = 120
CPU_HIST = 60
WAIT_MARKERS = ("CountDownLatch.await", "FutureTask.get", "Future.get", "Object.wait", "LockSupport.park")

# ---------------------------------------------------------------- локализация

STR = {
    # настройки
    "h_monitor": ("Мониторинг", "Monitoring"),
    "monitor": ("Следить за зависаниями", "Watch for freezes"),
    "monitor_sub": ("Проверка каждые 5 секунд, нагрузка ничтожная", "Checks every 5 seconds, negligible load"),
    "threshold": ("Зависанием считать после", "Treat as frozen after"),
    "notify": ("Уведомлять о зависании", "Notify about a freeze"),
    "rescue": ("Снимать самоблокировку базы", "Break database self-deadlock"),
    "rescue_sub": ("Если поток базы данных ждёт сам себя, прервать это ожидание. Приложение оживает без перезапуска",
                   "If the database thread is waiting for itself, interrupt that wait. The app recovers without a restart"),
    "ping": ("Тестовый запрос к серверу", "Server test request"),
    "ping_sub": ("Лёгкий запрос раз в 30 секунд. Отличает проблему сети от проблемы клиента",
                 "A light request every 30 s. Tells network problems from client problems"),
    "trace": ("Записывать вызовы getDifference", "Record getDifference calls"),
    "trace_sub": ("Точная хронология обновления. Применяется после перезапуска плагина",
                  "Exact update timeline. Applies after the plugin restarts"),
    "h_diag": ("Диагностика", "Diagnostics"),
    "status": ("Состояние сейчас", "Status now"),
    "unblock": ("Разблокировать сейчас", "Unblock now"),
    "h_reports": ("Отчёты", "Reports"),
    "show": ("Показать последний отчёт", "Show latest report"),
    "copy_short": ("Копировать краткий отчёт", "Copy short report"),
    "copy_full": ("Копировать полный отчёт", "Copy full report"),
    "send": ("Отправить отчёт в Избранное", "Send report to Saved Messages"),
    "journal": ("Журнал событий", "Event log"),
    "report_lang": ("Язык отчётов", "Report language"),
    "clear": ("Удалить отчёты и журнал", "Delete reports and log"),
    "stats": ("Статистика", "Statistics"),
    "stats_sub": ("Зависаний: {n} · снято автоматически: {m}", "Freezes: {n} · fixed automatically: {m}"),
    "about": (
        "Когда что-то ломается, плагин сам разбирается: при зависании обновления снимает стеки потоков и называет причину, "
        "а в фоне читает журнал Android и находит краши, исключения Python, ошибки плагинов и ANR прошлых запусков. "
        "Где возможно, он называет плагин-виновник. Отчёты переживают перезапуск приложения.\n\n"
        "Приватность: в отчёты попадают только строки с ошибками из журнала приложения. Номера длиннее 6 цифр, @имена и ссылки заменяются метками. "
        "Нет сообщений, номеров телефонов, названий чатов и адресов прокси. Есть версия приложения и Android, модель устройства, список плагинов и стеки потоков. Отчёт можно просмотреть до отправки.",
        "When something breaks the plugin investigates: on an update freeze it captures thread stacks and names the cause, "
        "and in the background it reads the Android log to find crashes, Python exceptions, plugin errors and ANRs from past launches. "
        "Where possible it names the culprit plugin. Reports survive an app restart.\n\n"
        "Privacy: reports contain only error lines from the app's own log. Numbers longer than 6 digits, @names and links are replaced by markers. "
        "No messages, phone numbers, chat names or proxy addresses. A report has the app and Android versions, the device model, the plugin list and thread stacks. You can read a report before sharing it."),
    # уведомления и диалоги
    "collecting": ("Собираю диагностику, около 20 секунд…", "Collecting diagnostics, about 20 seconds…"),
    "report_busy": ("Отчёт уже собирается", "A report is already being collected"),
    "no_reports": ("Отчётов пока нет", "No reports yet"),
    "copied": ("Скопировано", "Copied"),
    "sent": ("Отчёт отправлен в Избранное", "Report sent to Saved Messages"),
    "send_fail": ("Не удалось отправить: {e}", "Could not send: {e}"),
    "cleared": ("Удалено", "Deleted"),
    "rescue_none": ("Самоблокировки потока базы не найдено", "No database self-deadlock found"),
    "rescued": ("Прерван поток: {names}", "Interrupted thread: {names}"),
    "freeze_notify": ("Stall Doctor: обнаружено зависание. Отчёт готов, он в настройках плагина",
                      "Stall Doctor: a freeze was detected. The report is ready in the plugin settings"),
    "dlg_result": ("Результат диагностики", "Diagnostics result"),
    "dlg_last": ("Последний отчёт", "Latest report"),
    "dlg_journal": ("Журнал событий", "Event log"),
    "copy": ("Копировать", "Copy"),
    "empty": ("Пусто", "Empty"),
    "st_off": ("Мониторинг выключен", "Monitoring is off"),
    "st_freeze": ("ЗАВИСАНИЕ: {what}", "FREEZE: {what}"),
    "st_suspect": ("Подозрение", "Suspicious"),
    "st_ok": ("Всё в порядке", "All good"),
    "st_nodata": ("Нет данных", "No data"),
    # отчёт
    "r_title": ("Stall Doctor {v} · отчёт {ts} · {kind}", "Stall Doctor {v} · report {ts} · {kind}"),
    "r_manual": ("ручной", "manual"),
    "r_auto": ("авто", "auto"),
    "r_reason": ("Повод: {x}", "Reason: {x}"),
    "r_app": ("Версия приложения: {b} · аккаунт: {a}", "App version: {b} · account: {a}"),
    "s_verdict": ("ВЕРДИКТ", "VERDICT"),
    "s_probes": ("ПРОВЕРКИ КАНАЛОВ СЕЙЧАС", "CHANNEL CHECKS NOW"),
    "s_client": ("КЛИЕНТ TELEGRAM", "TELEGRAM CLIENT"),
    "s_stuck": ("ЗАСТРЯВШИЕ ПОТОКИ (стек не менялся {n} с)", "STUCK THREADS (stack unchanged for {n} s)"),
    "s_events": ("ХРОНОЛОГИЯ СОБЫТИЙ (последние 60)", "EVENT TIMELINE (last 60)"),
    "s_history": ("ИСТОРИЯ ПРОВЕРОК (последние 24 тика)", "CHECK HISTORY (last 24 ticks)"),
    "s_plugins": ("ПЛАГИНЫ", "PLUGINS"),
    "s_java": ("ЗНАЧИМЫЕ ПОТОКИ JAVA (второй снимок)", "RELEVANT JAVA THREADS (second snapshot)"),
    "s_python": ("ПОТОКИ PYTHON С АКТИВНЫМ КОДОМ (второй снимок)", "PYTHON THREADS WITH ACTIVE CODE (second snapshot)"),
    "p_ui": ("Главный UI-поток", "Main UI thread"),
    "p_plugins": ("Очередь плагинов", "Plugins queue"),
    "p_stage": ("stageQueue (ответы сервера и обновления)", "stageQueue (server answers and updates)"),
    "p_global": ("globalQueue", "globalQueue"),
    "p_ping": ("Запрос updates.getState к серверу", "updates.getState request to the server"),
    "pr_stuck": ("НЕ ОТВЕЧАЕТ уже {w} с", "NOT RESPONDING for {w} s"),
    "pr_lost": ("ответ терялся {n} раз", "answer was lost {n} times"),
    "pr_wait": ("ждём ответ {w} с", "waiting for answer {w} s"),
    "pr_notyet": ("ещё не проверялось", "not checked yet"),
    "pr_err": ("ошибка: {e}", "error: {e}"),
    "pr_off": ("выключено в настройках", "disabled in settings"),
    "c_state": ("Состояние соединения: {s}", "Connection state: {s}"),
    "c_net": ("Сеть Android: {n}", "Android network: {n}"),
    "c_proxy": ("Прокси включён: {p}", "Proxy enabled: {p}"),
    "c_paused": ("Приложение в фоне: {p}", "App in background: {p}"),
    "c_diff": ("Последний вызов getDifference: {t} ({a} с назад)", "Last getDifference call: {t} ({a} s ago)"),
    "c_upd": ("Последний setIsUpdating({v}): {t} ({a} с назад)", "Last setIsUpdating({v}): {t} ({a} s ago)"),
    "yes": ("да", "yes"),
    "no": ("нет", "no"),
    "unknown": ("неизвестно", "unknown"),
    "none_stuck": ("Таких потоков нет.", "None."),
    "hi_prio": ("[Python внутри Java-потока: сейчас выполняется код плагина] высокий приоритет",
                "[Python inside a Java thread: plugin code is running right now] high priority"),
    "low_prio": ("[Python-поток плагина «{n}»] часто это просто ожидание", "[Python thread of a plugin \"{n}\"] often just waiting"),
    "pl_none": ("Список из PluginsController не получен. Файлы в папке плагинов: {x}", "PluginsController list unavailable. Files in the plugins folder: {x}"),
    "pl_noresp": ("НЕ ОТВЕЧАЕТ", "NOT RESPONDING"),
    "pl_err": ("ОШИБКА", "ERROR"),
    "wd": ("Watchdog системы плагинов:", "Plugin system watchdog:"),
    "idle": ("Простаивают ({n}): {x}", "Idle ({n}): {x}"),
    "trunc": ("… дальше обрезано …", "… truncated …"),
    "kind_java": ("Java-поток внутри Python", "Java thread inside Python"),
    "kind_py": ("Python-поток «{n}»", "Python thread \"{n}\""),
    # вердикт
    "v_culprit": ("ВИНОВНИК: {who}. Сторонний код в застрявшем потоке: {pk}.", "CULPRIT: {who}. Third-party code in the stuck thread: {pk}."),
    "v_unnamed": ("плагин не определён по имени", "plugin could not be matched by name"),
    "v_advice": ("Что делать: отключите «{who}» или обновите его и приложите краткий отчёт к сообщению автору.",
                 "What to do: disable \"{who}\" or update it, and attach the short report to your message to the author."),
    "v_self": ("САМОБЛОКИРОВКА: поток {n} внутри MessagesStorage.{m}() ждёт результат, который должен выполнить он сам. Очередь базы ждёт саму себя и никогда не освободится.",
               "SELF-DEADLOCK: thread {n} inside MessagesStorage.{m}() waits for a result that only it can produce. The database queue waits for itself and never recovers."),
    "v_self_from": (" Вызов пришёл из стороннего кода: {pk}.", " The call came from third-party code: {pk}."),
    "v_waitdb": ("Поток {n} ждёт очередь базы данных внутри MessagesStorage.{m}(). Если очередь базы сама заблокирована, остановится и он.",
                 "Thread {n} waits for the database queue inside MessagesStorage.{m}(). If that queue is itself blocked, this thread stops too."),
    "v_foreign": ("Поток {n} застрял в стороннем коде: {pk}.", "Thread {n} is stuck in third-party code: {pk}."),
    "v_rescued": ("Автоматическая разблокировка: прерван поток {x}. Чаты должны ожить без перезапуска. Причина остаётся: вызов повторится, пока плагин не исправлен или не отключён.",
                  "Automatic unblock: interrupted thread {x}. Chats should recover without a restart. The cause remains: the call will repeat until the plugin is fixed or disabled."),
    "v_ui": ("Главный UI-поток не отвечает {w} с: интерфейс завис (похоже на ANR). Смотрите стек потока main.",
             "The main UI thread has not answered for {w} s: the interface is frozen (looks like an ANR). See the main thread stack."),
    "v_stage": ("ЗАТЫК В stageQueue ({w} с). Через неё идут ответы сервера и обновления, поэтому не грузится ничего. Кто держит очередь, видно в стеках ниже.",
                "STALL IN stageQueue ({w} s). Server answers and updates go through it, so nothing loads. The stacks below show who holds the queue."),
    "v_plugins": ("Очередь плагинов заблокирована {w} с, при этом stageQueue жива. Какой-то плагин выполняет в ней блокирующий вызов (сеть, ожидание ответа, lock). Хуки за этой очередью не отрабатывают.",
                  "The plugins queue has been blocked for {w} s while stageQueue is alive. Some plugin runs a blocking call in it (network, waiting for an answer, a lock). Hooks behind this queue do not run."),
    "v_global": ("globalQueue не отвечает {w} с.", "globalQueue has not answered for {w} s."),
    "v_net": ("Очереди живы, но запрос к серверу не возвращается {w} с, хотя Android видит сеть (состояние клиента: {s}). Проблема в соединении.{px}",
              "Queues are alive but the server request has not returned for {w} s although Android sees the network (client state: {s}). The problem is the connection.{px}"),
    "v_proxy": (" Прокси включён: он принимает соединение, но может не передавать данные. Проверьте другой прокси или отключите этот.",
                " A proxy is enabled: it may accept the connection but pass no data. Try another proxy or turn this one off."),
    "v_srv_err": ("Сервер отвечает на тестовый запрос ошибкой: {e}.", "The server answers the test request with an error: {e}."),
    "v_gd": ("Очереди живы и сервер отвечает, но клиент застрял в «Обновление»: getDifference не завершился.{x} Ответ потерян или не обработан внутри клиента. Частые причины: хук плагина, который отменяет или подменяет обновления (TL_updates*, getDifference), либо исключение в обработчике. Выключение системы плагинов снимает хуки, поэтому и помогает.",
             "Queues are alive and the server answers, but the client is stuck in \"Updating\": getDifference never finished.{x} The answer was lost or not processed inside the client. Common causes: a plugin hook that cancels or replaces updates (TL_updates*, getDifference), or an exception in a handler. Turning the plugin system off removes hooks, which is why it helps."),
    "v_gd_x": (" setIsUpdating(true) был {a} с назад и не сменился на false.", " setIsUpdating(true) was {a} s ago and never changed to false."),
    "v_waitnet": ("Клиент в состоянии «Ожидание сети», хотя Android сообщает, что сеть есть. Клиент не заметил возвращение сети. Бывает после долгой потери связи.",
                  "The client is in \"Waiting for network\" although Android reports a network. The client missed that the network came back. Happens after a long connectivity loss."),
    "v_conn": ("Клиент долго остаётся в «{s}», очереди живы. Смотрите прокси и сеть.", "The client stays in \"{s}\" for long while queues are alive. Check the proxy and the network."),
    "v_hard": ("Подозреваемые плагины (их код сейчас выполняется внутри Java-потока и не двигается): {x}.", "Suspect plugins (their code is running inside a Java thread and not moving): {x}."),
    "v_soft": ("Менее надёжные подозрения (Python-потоки этих плагинов не меняли стек, часто это обычное ожидание): {x}.", "Weaker suspicions (these plugins' Python threads did not change their stack, often just waiting): {x}."),
    "v_java": ("Есть застрявшие Java-потоки. Названия классов в их стеках подскажут, кто держит очередь.", "There are stuck Java threads. Class names in their stacks hint at who holds the queue."),
    "v_ok": ("Сейчас признаков зависания нет: очереди и сервер отвечают. Соберите отчёт в момент, когда проблема воспроизводится, либо дождитесь автоматического снимка.",
             "No sign of a freeze right now: queues and the server respond. Collect a report while the problem is happening, or wait for the automatic snapshot."),
    # здоровье системы
    "h_health": ("Здоровье системы", "System health"),
    "scan_logs": ("Сканировать журнал Android", "Scan the Android log"),
    "scan_logs_sub": ("Ищет краши, ошибки плагинов и разбирает падения и ANR прошлых запусков. Раз в 10 минут", "Looks for crashes and plugin errors and analyses past crashes and ANRs. Every 10 minutes"),
    "notify_issues": ("Уведомлять о проблемах", "Notify about problems"),
    "scan_now": ("Проверить систему сейчас", "Check the system now"),
    "issues": ("Обнаруженные проблемы", "Detected problems"),
    "scanning": ("Проверяю журнал, плагины и прошлые сбои…", "Checking the log, plugins and past crashes…"),
    "no_issues": ("Проблем не найдено", "No problems found"),
    "dlg_issues": ("Обнаруженные проблемы", "Detected problems"),
    "n_issue": ("Stall Doctor: {who}: {what}. Подробности в настройках плагина", "Stall Doctor: {who}: {what}. Details in the plugin settings"),
    "s_issues": ("ПРОБЛЕМЫ СИСТЕМЫ", "SYSTEM PROBLEMS"),
    "i_line": ("• [{who}] {what} (×{n}, {t})", "• [{who}] {what} (×{n}, {t})"),
    "who_unknown": ("плагин не определён", "plugin unknown"),
    "k_crash": ("Краш приложения", "App crash"),
    "k_pytrace": ("Исключение Python", "Python exception"),
    "k_plugin_log": ("Ошибка плагина в журнале", "Plugin error in the log"),
    "k_hook": ("Ошибка хука Xposed", "Xposed hook error"),
    "k_exit": ("Завершение процесса", "Process exit"),
    "k_plugin_state": ("Состояние плагина", "Plugin state"),
    "k_ui": ("UI-поток заблокирован", "UI thread blocked"),
    "k_memory": ("Мало памяти", "Low memory"),
    "i_state_err": ("ошибка загрузки или работы: {e}", "load or runtime error: {e}"),
    "i_state_noresp": ("плагин не отвечает", "plugin is not responding"),
    "i_ui": ("UI-поток не отвечал {w} с", "The UI thread did not answer for {w} s"),
    "i_mem": ("Куча заполнена на {p}% ({u} из {m} МБ)", "Heap is {p}% full ({u} of {m} MB)"),
    "c_mem": ("Память кучи: {u} из {m} МБ", "Heap memory: {u} of {m} MB"),
    "v_issues": ("Зависания сейчас нет, но найдены проблемы ({n}). Главные: {x}", "No freeze right now, but problems were found ({n}). Main ones: {x}"),
    "s_cpu": ("НАГРУЗКА НА CPU (среднее за последние {n} мин)", "CPU LOAD (average over the last {n} min)"),
    "cpu_line": ("{name}: {pct}%{who}", "{name}: {pct}%{who}"),
    "cpu_own": (" (Stall Doctor)", " (Stall Doctor)"),
    "cpu_who": (" (плагин: {x})", " (plugin: {x})"),
    "cpu_none": ("Данных о нагрузке ещё нет (замер раз в 2 минуты).", "No load data yet (sampled every 2 minutes)."),
    "k_cpu": ("Высокая нагрузка на CPU", "High CPU load"),
    "i_cpu": ("Процесс грузит CPU на {p}% ({mode}). Главные потоки: {x}", "The process uses {p}% CPU ({mode}). Top threads: {x}"),
    "mode_bg": ("в фоне", "in background"),
    "mode_fg": ("на экране", "on screen"),
    "i_cpu_exit": ("Android ограничил приложение за избыточную нагрузку на CPU в фоне. Нагрузка по потокам за последнее время:", "Android penalised the app for excessive background CPU use. Load by thread recently:"),
    "hint_cpu": ("Что это: Android ограничил приложение за нагрузку на процессор в фоне. Кто её создаёт, покажет раздел «Нагрузка на CPU» в полном отчёте после суток работы плагина.",
                 "What this is: Android penalised the app for CPU use in the background. The \"CPU load\" section of the full report shows who causes it after the plugin has run for a day."),
    "hint_anr": ("Что это: приложение зависло и было закрыто системой (ANR). Если плагин нашёл виновника, он указан слева, иначе смотрите стеки в полном отчёте.",
                 "What this is: the app froze and was closed by the system (ANR). If the plugin found the culprit it is named on the left, otherwise see the stacks in the full report."),
    "hint_mem": ("Что это: системе не хватало памяти. Отключите лишние плагины или перезапустите приложение.",
                 "What this is: the system ran low on memory. Disable unneeded plugins or restart the app."),
    "ui_lang": ("Язык интерфейса / Interface language", "Interface language / Язык интерфейса"),
    "sec_errors": ("Ошибки плагинов", "Plugin errors"),
    "h_errors": ("Слежение за ошибками", "Error tracking"),
    "err_watch": ("Следить за ошибками плагинов", "Watch plugins for errors"),
    "err_watch_sub": ("Читает журнал приложения и состояние плагинов, находит ошибки и называет плагин", "Reads the app log and plugin states, finds errors and names the plugin"),
    "err_interval": ("Как часто проверять", "How often to check"),
    "err_popup": ("Показывать окно с вариантами", "Show a popup with options"),
    "err_popup_sub": ("Что случилось и что можно сделать. Не чаще раза в 90 секунд", "What happened and what you can do. At most once per 90 seconds"),
    "err_level": ("Для каких ошибок окно", "Which errors get a popup"),
    "err_ignore": ("Не показывать окно для плагинов", "No popup for plugins"),
    "err_ignore_sub": ("Идентификаторы через запятую. Ошибки всё равно попадут в список", "Plugin ids separated by commas. Errors are still kept in the list"),
    "err_list": ("Ошибки по плагинам", "Errors by plugin"),
    "err_list_sub": ("Сводка: кто и сколько раз ошибся", "Summary: who failed and how many times"),
    "err_test": ("Проверить окно ошибки", "Test the error popup"),
    "err_test_sub": ("Покажет пример окна. Ничего не отключает", "Shows a sample popup. Disables nothing"),
    "err_none": ("Ошибок плагинов не найдено", "No plugin errors found"),
    "err_line": ("{who}: {n} шт., последняя: {what}", "{who}: {n}, latest: {what}"),
    "h_checks": ("Что проверять", "What to check"),
    "track_changes": ("Следить за установкой и обновлением плагинов", "Track plugin installs and updates"),
    "env_check": ("Проверять устройство (память, место, режим экономии)", "Check the device (memory, storage, power saving)"),
    "scan_exits": ("Разбирать причины прошлых завершений приложения", "Analyse past app exits"),
    "ep_disable": ("Отключить «{who}»", "Disable “{who}”"),
    "ep_more": ("Ещё…", "More…"),
    "ep_disabled": ("Плагин «{who}» отключён", "Plugin “{who}” was disabled"),
    "ep_disable_fail": ("Не удалось отключить «{who}»", "Could not disable “{who}”"),
    "ep_test_note": ("Это проверка окна, ничего не изменено", "This is a popup test, nothing was changed"),
    "ep_more_title": ("Другие варианты", "More options"),
    "ep_more_msg": ("Перезагрузка плагинов требует включённого расширенного режима. «Не показывать» убирает окна для этого плагина, ошибки останутся в списке.",
                    "Reloading plugins needs the advanced mode. “Hide” stops popups for this plugin; errors stay in the list."),
    "ep_reload": ("Перезагрузить плагины", "Reload plugins"),
    "ep_ignore": ("Не показывать «{who}»", "Hide “{who}”"),
    "ep_ignored": ("Окна для «{who}» отключены", "Popups for “{who}” are off"),
    "ep_details": ("Все ошибки", "All errors"),
    "ep_what": ("Что случилось", "What happened"),
    "ep_err": ("Ошибка", "Error"),
    "ep_where": ("Где", "Where"),
    "ep_count": ("Повторов: {n}, последний раз в {t}", "Repeats: {n}, last at {t}"),
    "ep_advice": ("Что делать: отключите плагин, если он не срочен, обновите его или отправьте автору текст ошибки (кнопка «Копировать»).",
                  "What to do: disable the plugin if it is not urgent, update it, or send the error text to its author (the Copy button)."),
    "ep_x_crash": ("Приложение упало, и в стеке найден код этого плагина.", "The app crashed and this plugin's code was found in the stack."),
    "ep_x_ui": ("Плагин заблокировал интерфейс: приложение перестало отвечать.", "The plugin blocked the interface: the app stopped responding."),
    "ep_x_exit": ("Система завершила приложение, в стеке найден этот плагин.", "The system terminated the app and this plugin was found in the stack."),
    "ep_x_pytrace": ("В коде плагина произошло необработанное исключение Python. Часть его функций могла перестать работать.",
                     "An unhandled Python exception occurred in the plugin. Some of its features may have stopped working."),
    "ep_x_plugin_state": ("exteraGram сообщает об ошибке при загрузке или работе плагина.", "exteraGram reports an error while loading or running the plugin."),
    "ep_x_plugin_log": ("Плагин записал ошибку в журнал приложения.", "The plugin wrote an error to the app log."),
    "ep_x_hook": ("Не удалось поставить или выполнить хук этого плагина.", "A hook of this plugin could not be installed or run."),
    "lv_all": ("Все ошибки плагинов", "All plugin errors"),
    "lv_serious": ("Только серьёзные: краши, зависания, исключения", "Serious only: crashes, freezes, exceptions"),
    "h_look": ("Вид и язык", "Look and language"),
    "h_popup": ("Окно с вариантами", "Popup with options"),
    "h_errview": ("Просмотр и проверка", "View and test"),
    "h_basic": ("Основное", "Basics"),
    "h_deep": ("Углублённый анализ", "Deep analysis"),
    "h_view": ("Посмотреть", "View"),
    "h_share": ("Отправить разработчику", "Send to a developer"),
    "h_hist": ("История и данные", "History and data"),
    "h_fix": ("Если что-то зависло", "If something is stuck"),
    "h_find": ("Найти виновника", "Find the culprit"),
    "h_test": ("Проверка и тесты", "Checks and tests"),
    "h_quick": ("Быстрые действия", "Quick actions"),
    "h_settings_lbl": ("Разделы настроек", "Settings sections"),
    "hint_deep": ("Эти функции нужны для точного поиска причин и немного нагружают приложение. Для обычного использования хватит основного",
                  "These help find exact causes and add a little load. Basics are enough for normal use"),
    "hint_hist": ("Отчёты хранятся только на устройстве, пока вы сами их не отправите", "Reports stay on the device until you send them yourself"),
    "hint_fix": ("Перезагрузка плагинов обычно помогает без перезапуска приложения", "Reloading plugins usually helps without restarting the app"),
    "cpu_warn": ("Предупреждать о нагрузке на CPU", "Warn about CPU load"),
    "cpu_warn_sub": ("Только если нагрузку создаёт названный плагин. Системные потоки (отрисовка, кэш) не считаются. Данные о нагрузке остаются в полном отчёте",
                     "Only when a named plugin causes the load. System threads (rendering, cache) do not count. Load data stays in the full report"),
    "issue_ttl": ("Забывать проблемы старше", "Forget problems older than"),
    "hide_lowmem": ("Не показывать закрытие в фоне из-за нехватки памяти", "Hide background closes caused by low memory"),
    "hide_lowmem_sub": ("Так Android обычно чистит память у свёрнутых приложений, это не сбой. Закрытия на экране всё равно покажутся",
                        "That is how Android normally frees memory from background apps, not a failure. Closes while on screen are still shown"),
    "clr_issues_sub": ("Удалит список. Старые события из журнала и истории Android обратно не вернутся",
                       "Clears the list. Old events from the log and Android history will not come back"),
    "clr_issues": ("Очистить список проблем", "Clear the problem list"),
    "st_issues": (" · проблем: {n}", " · problems: {n}"),
    "st_last": (" · последнее зависание {d} назад", " · last freeze {d} ago"),
    # защита частей, стоимость, лаги интерфейса, операции, уведомления, рейтинг, просмотр, пакет, обновления, разделы
    "c_parts": ("Части плагина, отключённые из-за повторных сбоев: {x}", "Plugin parts switched off after repeated failures: {x}"),
    "e_part_dead": ("часть «{n}» отключена после повторных сбоев до перезапуска плагина", "part \"{n}\" switched off after repeated failures until the plugin restarts"),
    "s_self": ("СТОИМОСТЬ САМОГО ПЛАГИНА", "COST OF THE PLUGIN ITSELF"),
    "sc_cpu": ("CPU: около {p}% в среднем за {n} мин (потоки меньше 0,3% не видны)", "CPU: about {p}% on average over {n} min (threads under 0.3% are not visible)"),
    "sc_swallow": ("Тихо перехваченные внутренние ошибки: {n} (мест: {k}; часть из них ожидаема при чтении полей Java)", "Silently caught internal errors: {n} ({k} places; some are expected when probing Java fields)"),
    "sc_threads": ("Потоков плагина сейчас: {n}", "Plugin threads now: {n}"),
    "sc_disk": ("Файлы на диске: {k} КБ в {n} файлах", "Files on disk: {k} KB in {n} files"),
    "sc_state": ("Сохранённое состояние в настройках: {k} КБ", "Saved state in settings: {k} KB"),
    "sc_btn": ("Стоимость плагина", "Cost of the plugin"),
    "sc_btn_sub": ("Сколько ресурсов тратит сам Stall Doctor", "How many resources Stall Doctor itself uses"),
    "jank_watch": ("Ловить микрозависания интерфейса", "Catch small UI freezes"),
    "jank_sub": ("Только когда приложение на экране: 5 лёгких проверок в секунду, при задержке больше 150 мс снимает стек главного потока. Выключено по умолчанию",
                 "Only while the app is on screen: 5 light checks per second, captures the main thread stack on a delay over 150 ms. Off by default"),
    "s_jank": ("МИКРОЗАВИСАНИЯ ИНТЕРФЕЙСА", "UI MICRO-FREEZES"),
    "jk_hist": ("Задержка главного потока, раз: до 50 мс {a} · 50–100 мс {b} · 100–200 мс {c} · 200–500 мс {d} · больше 500 мс {e}; худшая {w} мс",
                "Main thread delay, times: under 50 ms {a} · 50–100 ms {b} · 100–200 ms {c} · 200–500 ms {d} · over 500 ms {e}; worst {w} ms"),
    "jk_tops": ("Где чаще застревает: {x}", "Where it stalls most: {x}"),
    "jk_plug": ("Плагины в стеках задержек: {x}", "Plugins in delay stacks: {x}"),
    "jk_none": ("Наблюдение выключено или данных ещё нет", "Watching is off or there is no data yet"),
    "k_jank": ("Микрозависания интерфейса", "UI micro-freezes"),
    "i_jank": ("Задержек главного потока больше 200 мс за 10 минут: {n}", "Main thread delays over 200 ms in 10 minutes: {n}"),
    "op_timing": ("Замерять время операций", "Time operations"),
    "op_sub": ("Отправка сообщений, загрузка истории и списка чатов. Ставит три лёгких хука на запросы. Применяется после перезапуска плагина. Выключено по умолчанию",
               "Sending messages, loading history and the chat list. Adds three light request hooks. Applies after the plugin restarts. Off by default"),
    "s_ops": ("ВРЕМЯ ОПЕРАЦИЙ", "OPERATION TIMES"),
    "ops_line": ("{n}: {c} шт., ошибок {e}, среднее {a} мс, медиана {m} мс, 95% {p} мс, максимум {x} мс", "{n}: {c} calls, {e} errors, average {a} ms, median {m} ms, 95% {p} ms, max {x} ms"),
    "ops_none": ("Замер выключен или данных ещё нет", "Timing is off or there is no data yet"),
    "v_opslow": ("Операции стали заметно медленнее: {x}. Сравните с моментом, когда менялись плагины или приложение.", "Operations got much slower: {x}. Compare with when plugins or the app changed."),
    "env_notif": ("Уведомления разрешены: {v}", "Notifications allowed: {v}"),
    "env_blocked": ("Выключенные каналы уведомлений: {x}", "Blocked notification channels: {x}"),
    "env_dnd": ("Режим «Не беспокоить»: {v}", "Do Not Disturb: {v}"),
    "env_dnd_1": ("выключен", "off"),
    "env_dnd_2": ("только важные", "priority only"),
    "env_dnd_3": ("полная тишина", "total silence"),
    "env_dnd_4": ("только будильники", "alarms only"),
    "env_bucket": ("Группа ожидания приложения (Android): {v}", "App standby bucket (Android): {v}"),
    "env_bgrestr": ("Фоновая работа ограничена системой: {v}", "Background work restricted by the system: {v}"),
    "env_push": ("Push-токен получен: {v}", "Push token received: {v}"),
    "env_proc": ("Процесс живёт {u}, плагин загружен через {l} после его запуска", "The process has lived {u}, the plugin loaded {l} after it started"),
    "k_notif": ("Уведомления могут не приходить", "Notifications may not arrive"),
    "i_notif_off": ("Уведомления приложения выключены в системе", "App notifications are switched off in the system"),
    "i_bgrestr": ("Система ограничила фоновую работу приложения", "The system restricted the app's background work"),
    "i_bucket": ("Приложение в редкой группе ожидания Android ({b}): push и фоновые задачи задерживаются", "The app is in a rare Android standby bucket ({b}): push and background tasks are delayed"),
    "i_nopush": ("Push-токен не получен: уведомления в фоне не придут", "No push token: background notifications will not arrive"),
    "rk_stack": ("код в застрявшем потоке", "code in a stuck thread"),
    "rk_pyfrozen": ("Python внутри Java-потока", "Python inside a Java thread"),
    "rk_pywait": ("Python-поток ждёт", "Python thread waiting"),
    "rk_issue": ("{k}", "{k}"),
    "rk_changed": ("недавно менялся", "changed recently"),
    "rk_hooks": ("хуки на обновления", "update hooks"),
    "rk_history": ("уже назывался виновником", "named a culprit before"),
    "v_rank": ("Рейтинг подозреваемых (очки: причины): {x}", "Suspect ranking (score: reasons): {x}"),
    "pv_title": ("Просмотр перед отправкой", "Review before sending"),
    "pv_head": ("Файл {name}: {k} КБ, {n} строк. Заменено на метки (ссылки, @имена, длинные числа): строк {m}", "File {name}: {k} KB, {n} lines. Replaced by markers (links, @names, long numbers): {m} lines"),
    "pv_nomarks": ("Строк с метками замены нет", "No lines with replacement markers"),
    "pv_start": ("Начало отчёта:", "Start of the report:"),
    "pv_send": ("Отправить в Избранное", "Send to Saved Messages"),
    "pv_copy": ("Копировать", "Copy"),
    "pv_close": ("Закрыть", "Close"),
    "bn_btn": ("Пакет для баг-репорта", "Bug report bundle"),
    "bn_building": ("Собираю пакет…", "Building the bundle…"),
    "h_sections": ("Разделы", "Sections"),
    "sec_monitor": ("Мониторинг и сеть", "Monitoring and network"),
    "sec_monitor_sub": ("Что и как проверять, пороги, лаги интерфейса, замер операций", "What to check and how, thresholds, UI freezes, operation timing"),
    "sec_recover_sub": ("Перезагрузка, деление пополам, проверка потери сети", "Reload, bisecting, network loss test"),
    "sec_health": ("Здоровье системы", "System health"),
    "sec_health_sub": ("Проблемы, самопроверка, изменения плагинов", "Problems, self-check, plugin changes"),
    "sec_reports": ("Отчёты и история", "Reports and history"),
    "sec_more": ("Дополнительно", "More"),
    "sec_more_sub": ("Стоимость плагина, перенос настроек", "Cost of the plugin, settings transfer"),
    "flat": ("Все настройки одной страницей", "All settings on one page"),
    "flat_sub": ("Если вложенные страницы не открываются", "If the nested pages do not open"),
    # расширенные действия, изменения, прокси, история, деление пополам, окружение
    "adv": ("Расширенные действия", "Advanced actions"),
    "adv_sub": ("Перезапуск приложения, перезагрузка плагинов, отключение плагинов при делении пополам, ручное прерывание потоков",
                "App restart, plugin reload, switching plugins off while bisecting, manual thread interruption"),
    "adv_need": ("Сначала включите «Расширенные действия» в настройках плагина", "Turn on \"Advanced actions\" in the plugin settings first"),
    "observer": ("Ловить переходы соединения событиями", "Catch connection changes by events"),
    "observer_sub": ("Точное время каждого перехода, без ожидания очередной проверки. Применяется после перезапуска плагина",
                     "Exact time of every transition without waiting for the next check. Applies after the plugin restarts"),
    "chg_new": ("установлен", "installed"),
    "chg_updated": ("обновлён {a} → {b}", "updated {a} → {b}"),
    "chg_enabled": ("включён", "enabled"),
    "chg_disabled": ("выключен", "disabled"),
    "chg_removed": ("удалён", "removed"),
    "chg_title": ("Изменения плагинов за 2 недели", "Plugin changes over 2 weeks"),
    "chg_none": ("Изменений не замечено", "No changes noticed"),
    "chg_btn": ("Изменения плагинов", "Plugin changes"),
    "chg_btn_sub": ("Что установили, обновили, включили или удалили", "What was installed, updated, enabled or removed"),
    "ago": ("{d} назад", "{d} ago"),
    "s_changes": ("ИЗМЕНЕНИЯ ПЛАГИНОВ (за 2 недели)", "PLUGIN CHANGES (last 2 weeks)"),
    "v_changes": ("Перед зависанием менялись плагины: {x}. Новые поломки чаще всего идут от того, что менялось последним.",
                  "Plugins changed shortly before: {x}. New breakage most often comes from whatever changed last."),
    "e_upd_took": ("«Updating» длилось {d}", "\"Updating\" lasted {d}"),
    "s_conn": ("ПЕРЕХОДЫ СОЕДИНЕНИЯ (последние 20)", "CONNECTION TRANSITIONS (last 20)"),
    "px_off": ("выключен", "off"),
    "e_proxy": ("прокси: {a} → {b}", "proxy: {a} → {b}"),
    "c_proxy_hist": ("Смен прокси за последний час: {n}", "Proxy changes in the last hour: {n}"),
    "v_proxychg": ("Прокси менялся {d} назад: зависание могло начаться из-за переключения. Проверьте, отвечает ли новый прокси.",
                   "The proxy changed {d} ago: the freeze may come from the switch. Check that the new proxy answers."),
    "v_proxyflap": ("Прокси переключался {n} раз за час. Частая смена сама рвёт соединение и сбивает клиента.",
                    "The proxy switched {n} times in an hour. Frequent switching itself breaks the connection and confuses the client."),
    "ep_btn": ("История зависаний", "Freeze history"),
    "ep_btn_sub": ("Длительность, причины и закономерности", "Duration, causes and patterns"),
    "ep_csv": ("Копировать историю таблицей (CSV)", "Copy the history as a table (CSV)"),
    "ep_title": ("История зависаний", "Freeze history"),
    "ep_none": ("Зависаний ещё не было", "No freezes yet"),
    "ep_total": ("Зависаний: {n}", "Freezes: {n}"),
    "ep_avg": ("Средняя длительность: {d}", "Average duration: {d}"),
    "ep_off": ("После потери сети: {k} из {n}", "After a network loss: {k} of {n}"),
    "ep_chg": ("После изменения плагинов: {k} из {n}", "After a plugin change: {k} of {n}"),
    "ep_px": ("После смены прокси: {k} из {n}", "After a proxy change: {k} of {n}"),
    "ep_cul": ("Чаще всего назывались: {x}", "Named most often: {x}"),
    "ep_rec": ("Что помогало (помогло/попыток): {x}", "What helped (helped/attempts): {x}"),
    "v_pat_off": ("Закономерность: {k} из {n} зависаний начались после потери сети.", "Pattern: {k} of {n} freezes began after a network loss."),
    "v_pat_chg": ("Закономерность: {k} из {n} зависаний начались вскоре после изменения плагинов.", "Pattern: {k} of {n} freezes began soon after a plugin change."),
    "v_pat_px": ("Закономерность: {k} из {n} зависаний начались вскоре после смены прокси.", "Pattern: {k} of {n} freezes began soon after a proxy change."),
    "bis": ("Деление пополам", "Bisect"),
    "bis_btn": ("Деление пополам: найти плагин-виновник", "Bisect: find the culprit plugin"),
    "bis_sub": ("Выключает половину плагинов, вы повторяете сценарий и отвечаете, зависло ли. Раунд за раундом остаётся один. Нужны «Расширенные действия»; метод отключения в этой сборке не подтверждён",
                "Switches half of the plugins off, you repeat the scenario and say whether it froze. Round by round one is left. Needs \"Advanced actions\"; the switching method is not confirmed in this build"),
    "bis_state": ("Идёт: раунд {r}, подозреваемых {n}, выключено {d}. Нажмите, чтобы ответить", "In progress: round {r}, {n} suspects, {d} switched off. Tap to answer"),
    "bis_confirm": ("Будет выключена половина включённых плагинов, кроме исключений из настройки ниже. Прокси-плагины лучше добавить в исключения: без них можно потерять связь. Начать?",
                    "Half of the enabled plugins will be switched off, except those listed in the setting below. Add proxy plugins to the exceptions: without them you may lose connectivity. Start?"),
    "bis_keep": ("Не выключать при делении пополам", "Do not switch off while bisecting"),
    "bis_keep_sub": ("id плагинов через запятую", "plugin ids separated by commas"),
    "bis_ask": ("Раунд {r}. Подозреваемых: {n}. Сейчас выключены: {d}.\n\nПовторите сценарий, при котором зависает. Зависло?",
                "Round {r}. Suspects: {n}. Switched off now: {d}.\n\nRepeat the scenario that freezes. Did it freeze?"),
    "bis_yes": ("Зависло", "Froze"),
    "bis_no": ("Не зависло", "Did not freeze"),
    "bis_cancel": ("Отменить и вернуть плагины", "Cancel and restore plugins"),
    "bis_done": ("Виновник: {p}. Он выключен, остальные плагины включены. Можно отправить автору «Отчёт по плагину».",
                 "Culprit: {p}. It is switched off, the other plugins are enabled. You can send the author a \"Report on a plugin\"."),
    "bis_few": ("Нужно минимум два включённых плагина вне исключений", "At least two enabled plugins outside the exceptions are needed"),
    "bis_failed": ("Не удалось переключить плагины в этой сборке", "Could not switch plugins in this build"),
    "e_bis_start": ("деление пополам: подозреваемых {n}", "bisect: {n} suspects"),
    "e_bis_round": ("деление пополам: раунд {r}, осталось {n}", "bisect: round {r}, {n} left"),
    "e_bis_done": ("деление пополам: виновник {p}", "bisect: culprit {p}"),
    "e_bis_cancel": ("деление пополам отменено, плагины возвращены", "bisect cancelled, plugins restored"),
    "s_env": ("ОКРУЖЕНИЕ", "ENVIRONMENT"),
    "env_battery": ("Оптимизация батареи отключена для приложения: {v}", "Battery optimisation disabled for the app: {v}"),
    "env_datasaver": ("Экономия трафика: {v}", "Data saver: {v}"),
    "env_ds_white": ("включена, приложение в исключениях", "on, app is whitelisted"),
    "env_free": ("Свободно места: {m} МБ", "Free space: {m} MB"),
    "env_safe": ("Безопасный режим плагинов: {v}", "Plugin safe mode: {v}"),
    "env_engine": ("Движок плагинов включён: {v}", "Plugin engine on: {v}"),
    "env_plugins": ("Плагинов включено: {n} из {m}", "Plugins enabled: {n} of {m}"),
    "k_storage": ("Мало места на устройстве", "Low storage"),
    "k_safemode": ("Безопасный режим плагинов", "Plugin safe mode"),
    "k_threads": ("Рост числа потоков", "Thread growth"),
    "k_fd": ("Много открытых файлов", "Many open files"),
    "k_memtrend": ("Рост памяти", "Memory growth"),
    "k_pythreads": ("Утечка потоков плагина", "Plugin thread leak"),
    "i_storage": ("Свободно {m} МБ", "{m} MB free"),
    "i_safemode": ("Движок плагинов в безопасном режиме: часть плагинов может быть отключена", "The plugin engine is in safe mode: some plugins may be switched off"),
    "i_threads": ("Потоков было {a}, стало {b}. Больше всего: {x}", "Threads went from {a} to {b}. Most: {x}"),
    "i_fd": ("Открытых файлов: {n} (было {a})", "Open files: {n} (was {a})"),
    "i_memtrend": ("Средняя память кучи выросла с {a} до {b} МБ за {m} мин", "Average heap grew from {a} to {b} MB in {m} min"),
    "i_pythreads": ("Потоков Python у плагина выросло с {a} до {b}", "The plugin's Python threads grew from {a} to {b}"),
    "i_state_disabled_err": ("плагин выключен из-за ошибки: {e}", "plugin was switched off because of an error: {e}"),
    "hooks_shared": ("Одни и те же хуки у нескольких плагинов: {x}", "The same hooks in several plugins: {x}"),
    # восстановление
    "h_recover": ("Восстановление и проверки", "Recovery and tests"),
    "rec_reload": ("Перезагрузить систему плагинов", "Reload the plugin system"),
    "rec_reload_sub": ("Выключает и включает движок плагинов. Экспериментально: схема из Plugin Restarter, на устройстве не подтверждена",
                       "Switches the plugin engine off and on. Experimental: the Plugin Restarter scheme, not confirmed on a device"),
    "rec_restart": ("Перезапустить приложение", "Restart the app"),
    "rec_restart_sub": ("Полный перезапуск. Результат запоминается, чтобы сравнить оба способа", "A full restart. The result is remembered to compare both methods"),
    "rec_stats": ("Что помогало раньше", "What helped before"),
    "rec_none": ("Попыток ещё не было", "No attempts yet"),
    "rec_title": ("Восстановление", "Recovery"),
    "rec_confirm_reload": ("Система плагинов будет выключена и включена заново. Если за 25 секунд не получится, приложение перезапустится само. Продолжить?",
                           "The plugin system will be switched off and on again. If it does not finish in 25 seconds the app restarts by itself. Continue?"),
    "rec_confirm_restart": ("Приложение закроется и откроется заново. Продолжить?", "The app will close and open again. Continue?"),
    "rec_yes": ("помогло", "helped"),
    "rec_no": ("не помогло", "did not help"),
    "rec_toast": ("Результат «{a}»: {r}", "Result of \"{a}\": {r}"),
    "rec_no_engine": ("В этой сборке нет нужных методов", "This build lacks the needed methods"),
    "act_reload": ("перезагрузка плагинов", "plugin reload"),
    "act_restart": ("перезапуск приложения", "app restart"),
    "go": ("Выполнить", "Do it"),
    "cancel": ("Отмена", "Cancel"),
    "e_rec_start": ("восстановление: {a}", "recovery: {a}"),
    "e_rec_done": ("восстановление «{a}»: {r} (состояние до: {s})", "recovery \"{a}\": {r} (state before: {s})"),
    "v_recovery": ("История восстановлений (помогло/попыток): {x}. Начните с того, что помогало.",
                   "Recovery history (helped/attempts): {x}. Start with what helped before."),
    # самопроверка и хуки
    "selfcheck": ("Самопроверка совместимости", "Compatibility self-check"),
    "selfcheck_sub": ("Какие внутренние классы и методы найдены в этой сборке: {ok} из {n}", "Which internal classes and methods exist in this build: {ok} of {n}"),
    "selfcheck_wait": ("Проверка ещё не завершилась", "The check has not finished yet"),
    "e_selfcheck": ("самопроверка: не найдено — {x}", "self-check: missing — {x}"),
    "s_selfcheck": ("САМОПРОВЕРКА СОВМЕСТИМОСТИ", "COMPATIBILITY SELF-CHECK"),
    "s_hooks": ("ХУКИ ПО ПЛАГИНАМ (лучшая попытка)", "HOOKS BY PLUGIN (best effort)"),
    "hooks_none": ("Реестр хуков в контроллере не найден. Запустите «Диагностика контроллера плагинов» и пришлите дамп.",
                   "No hook registry found in the controller. Run \"Plugin controller diagnostics\" and send the dump."),
    "hooks_line": ("{p}: хуков {n}{x}", "{p}: {n} hooks{x}"),
    "v_hooklist": ("Плагины, чьи хуки касаются обновлений: {x}. Это не доказательство, но деление пополам стоит начать с них.",
                   "Plugins with hooks on updates: {x}. Not proof, but start the bisecting with them."),
    "dump": ("Диагностика контроллера плагинов", "Plugin controller diagnostics"),
    "dump_sub": ("Пишет в файл поля и методы PluginsController, Plugin, движка и ExteraConfig. Нужна, чтобы найти реестр хуков",
                 "Writes the fields and methods of PluginsController, Plugin, the engine and ExteraConfig to a file. Needed to find the hook registry"),
    "dump_done": ("Дамп сохранён: {f}. Полей и методов, похожих на хуки: {n}", "Dump saved: {f}. Fields and methods that look like hooks: {n}"),
    "dump_send": ("Отправить дамп в Избранное", "Send the dump to Saved Messages"),
    "no_dump": ("Дампа ещё нет", "No dump yet"),
    "dumping": ("Снимаю дамп…", "Taking the dump…"),
    # проверка потери сети
    "sim": ("Проверка: потеря сети", "Test: network loss"),
    "sim_sub": ("Ведёт через сценарий «режим полёта → возврат сети» и сама снимает отчёт. Повторное нажатие отменяет",
                "Walks through the airplane-mode scenario and takes a report. Tap again to cancel"),
    "sim_off": ("Включите режим полёта: жду до 3 минут", "Turn airplane mode on: waiting up to 3 minutes"),
    "sim_down": ("Сеть пропала. Подержите режим полёта сколько нужно, затем выключите", "The network is gone. Keep airplane mode as long as needed, then turn it off"),
    "sim_up": ("Сеть вернулась после {d}. Отчёт через 90 секунд", "The network is back after {d}. A report in 90 seconds"),
    "sim_abort": ("Проверка прервана", "Test aborted"),
    "sim_reason": ("проверка потери сети ({d})", "network loss test ({d})"),
    # задержки
    "lat_profile": ("Профиль задержек очередей", "Queue latency profile"),
    "lat_sub": ("Средняя и максимальная задержка по 15 минут за 6 часов. Показывает медленную деградацию", "Average and maximum latency per 15 minutes over 6 hours. Shows slow degradation"),
    "s_lat": ("ЗАДЕРЖКИ ОЧЕРЕДЕЙ (по 15 минут)", "QUEUE LATENCY (15-minute buckets)"),
    "lat_none": ("Данных пока нет", "No data yet"),
    "v_slow": ("Очереди тормозят заметно сильнее обычного: {x}. Так выглядит медленная деградация перед полным зависанием.",
               "Queues are much slower than usual: {x}. This is what slow degradation before a full freeze looks like."),
    # отчёт по плагину
    "pr_btn": ("Отчёт по плагину…", "Report on a plugin…"),
    "pr_btn_sub": ("Короткий текст для автора: проблемы, хуки и стеки только этого плагина", "A short text for the author: problems, hooks and stacks of this plugin only"),
    "pr_pick": ("Выберите плагин", "Pick a plugin"),
    "pr_head": ("Stall Doctor {v} · отчёт по плагину {p} · {ts}", "Stall Doctor {v} · report on plugin {p} · {ts}"),
    "pr_state": ("Состояние: версия {v}, включён: {e}{f}", "State: version {v}, enabled: {e}{f}"),
    "pr_culprit": ("Назывался виновником в отчётах: {n} раз", "Named as a culprit in reports: {n} times"),
    "pr_issues": ("Проблемы:", "Problems:"),
    "pr_hooks": ("Хуки: {n}{x}", "Hooks: {n}{x}"),
    "pr_report": ("Упоминания в последнем отчёте:", "Mentions in the latest report:"),
    "pr_none": ("Следов этого плагина в отчётах и проблемах не найдено", "No traces of this plugin in reports or problems"),
    "pl_culprit_n": ("виновник ×{n}", "culprit ×{n}"),
    "pl_has_issues": ("есть проблемы", "has problems"),
    "pl_known": (" [известный виновник ×{n}]", " [known culprit ×{n}]"),
    # прочее
    "auto_send": ("Отправлять отчёт в Избранное сам", "Send the report to Saved Messages automatically"),
    "auto_send_sub": ("После автоматического отчёта о зависании, не чаще раза в 6 часов", "After an automatic freeze report, at most once in 6 hours"),
    "cfg_export": ("Копировать настройки", "Copy settings"),
    "cfg_import": ("Вставить настройки из буфера", "Paste settings from the clipboard"),
    "cfg_done": ("Настройки применены", "Settings applied"),
    "cfg_bad": ("В буфере нет настроек Stall Doctor", "The clipboard has no Stall Doctor settings"),
    # настройки сети и обновлений
    "h_net": ("Сеть и обновления", "Network and updates"),
    "net_track": ("Следить за потерей сети", "Track network loss"),
    "net_track_sub": ("Помнит, на сколько пропадала сеть, и связывает это с зависанием", "Remembers how long the network was down and links it to a freeze"),
    "storm": ("Искать шторм getDifference", "Detect getDifference storms"),
    "storm_sub": ("Сколько вызовов в минуту считать зацикливанием обновлений", "How many calls per minute count as an update loop"),
    "offline": ("Потеря сети важна, если дольше", "Network loss matters if longer than"),
    "rep_acc": ("Аккаунты в отчёте", "Accounts in the report"),
    "rep_acc_sub": ("Состояние соединения каждого активного аккаунта", "Connection state of every active account"),
    "auto_nudge": ("Подталкивать соединение само", "Nudge the connection automatically"),
    "auto_nudge_sub": ("Один раз за зависание, только если клиент в «Ожидании сети», а Android сеть видит. Экспериментально",
                       "Once per freeze, only if the client is in \"Waiting for network\" while Android sees a network. Experimental"),
    # сеть, шторм getDifference, толчок
    "nudge": ("Подтолкнуть соединение (экспериментально)", "Nudge the connection (experimental)"),
    "nudge_sub": ("Просит клиент перепроверить сеть без перезапуска приложения. Помогает, если клиент застрял в «Ожидание сети»",
                  "Asks the client to re-check the network without restarting the app. Helps when the client is stuck in \"Waiting for network\""),
    "nudged": ("Вызвано: {x}. Соединение: {a} → {b}", "Called: {x}. Connection: {a} → {b}"),
    "nudge_none": ("Подходящих методов в этой сборке не найдено", "No suitable methods found in this build"),
    "e_nudge": ("толчок соединения: {x}; {a} → {b}", "connection nudge: {x}; {a} → {b}"),
    "e_net_lost": ("сеть Android пропала", "Android network lost"),
    "e_net_back": ("сеть вернулась после {d} без связи", "network is back after {d} offline"),
    "c_accounts": ("Аккаунты: {x}", "Accounts: {x}"),
    "c_offline_now": ("Сети Android нет уже {d}", "No Android network for {d}"),
    "c_offline_last": ("Последняя потеря сети: {d}, закончилась {a} мин назад", "Last network loss: {d}, ended {a} min ago"),
    "c_gdrate": ("Вызовов getDifference за последнюю минуту: {n}", "getDifference calls in the last minute: {n}"),
    "v_gdstorm": ("getDifference вызывается слишком часто: {n} раз за минуту. Клиент крутится в цикле догоняния обновлений: ответ не принимается или сразу отбрасывается. Первым делом проверьте плагины с хуками на TL_updates* и getDifference.",
                  "getDifference is called too often: {n} times in a minute. The client loops catching up on updates: the answer is not accepted or is dropped at once. First check plugins that hook TL_updates* and getDifference."),
    "v_offline": ("Перед этим сеть пропадала на {d}. Это сценарий «чаты не обновляются после долгой потери связи». Нажмите «Подтолкнуть соединение»: если поможет, застрял клиент, а не плагин. Если нет, сравните перезагрузку плагинов с полным перезапуском приложения.",
                  "The network was down for {d} just before. This is the \"chats stop updating after a long connectivity loss\" scenario. Try \"Nudge the connection\": if it helps, the client got stuck, not a plugin. If not, compare a plugin reload with a full app restart."),
    # журнал
    "e_started": ("плагин запущен, версия {v}", "plugin started, version {v}"),
    "e_unloaded": ("плагин выгружен", "plugin unloaded"),
    "e_sleep": ("устройство спало или сторож был заморожен ({lag} с), счётчики сброшены", "device slept or the watchdog was frozen ({lag} s), counters reset"),
    "e_freeze": ("ЗАВИСАНИЕ: {x}", "FREEZE: {x}"),
    "e_freeze_again": ("ЗАВИСАНИЕ вернулось (тот же эпизод): {x}", "FREEZE is back (same episode): {x}"),
    "e_log_clock": ("время в журнале ушло назад на {d}: курсор журнала сброшен", "log time went back by {d}: log cursor reset"),
    "logchk_btn": ("Проверить чтение журнала", "Check log reading"),
    "logchk_btn_sub": ("Пишет тестовые строки и проверяет, что плагин находит их в logcat и разбирает", "Writes test lines and checks that the plugin finds and parses them from logcat"),
    "logchk_busy": ("Проверка идёт…", "Checking…"),
    "logchk_title": ("Проверка журнала", "Log check"),
    "e_app_changed": ("версия приложения изменилась: {a} → {b}", "app version changed: {a} → {b}"),
    "app_chg_line": ("Версия приложения изменилась {t}: {a} → {b}.", "App version changed {t}: {a} → {b}."),
    "app_chg_lost": ("После обновления перестали находиться: {x}.", "After the update these are no longer found: {x}."),
    "app_chg_ok": ("Из того, что находилось раньше, ничего не пропало.", "Nothing that was found before is missing."),
    "v_appchg": ("Недавно изменилась версия приложения ({a} → {b}), и после этого не находятся: {x}. Возможна несовместимость плагина с новой сборкой.",
                 "The app version changed recently ({a} → {b}) and these are no longer found: {x}. A plugin may be incompatible with the new build."),
    "v_rec_reload": ("Перезагрузка плагинов обычно помогает ({h} из {n}): причина, скорее всего, в живом коде или хуке плагина, а не в клиенте. Ищите виновника делением пополам.",
                     "Reloading plugins usually helps ({h} of {n}): the cause is most likely live plugin code or a hook, not the client. Look for the culprit by bisecting."),
    "v_rec_restart": ("Перезагрузка плагинов не помогает ({h} из {n}), а полный перезапуск помогает ({h2} из {n2}): застрявшее состояние, вероятно, в самом клиенте (соединение, MessagesController), а не в Python-плагине.",
                      "Reloading plugins does not help ({h} of {n}) but a full restart does ({h2} of {n2}): the stuck state is probably in the client itself (connection, MessagesController), not in a Python plugin."),
    "chg_sysdisabled": ("выключен, у плагина ошибка: {e} (похоже, отключён системой)", "disabled, the plugin has an error: {e} (looks like it was disabled by the system)"),
    "e_recovered": ("всё восстановилось", "everything recovered"),
    "e_conn": ("соединение: {a} → {b} (сеть Android: {n})", "connection: {a} → {b} (Android network: {n})"),
    "e_interrupt": ("РАЗБЛОКИРОВКА: прерван поток {n}", "UNBLOCK: interrupted thread {n}"),
    "e_saved": ("отчёт сохранён: {f}. Вердикт: {v}", "report saved: {f}. Verdict: {v}"),
    "d_problem": ("{n} не отвечает {w} с", "{n} not responding for {w} s"),
    "d_cond": ("{k} уже {w} с", "{k} for {w} s already"),
}

# --- v3.8: простое меню, понятное окно проблем -------------------------------------------------
STR.update({
    "collect": ("Собрать полный отчёт (около 20 с)", "Collect a full report (~20 s)"),
    "collect_sub": ("Снимок потоков и проверки. Потом отчёт можно скопировать или отправить",
                    "A thread snapshot and checks. You can then copy or send the report"),
    "issues_sub": ("Найдено: {n}. Что не так и что делать", "Found: {n}. What is wrong and what to do"),
    "issues_sub0": ("Пока всё чисто. Можно проверить вручную", "All clear so far. You can run a check by hand"),
    "last_report": ("Последний отчёт", "Latest report"),
    "last_report_sub": ("Открыть, скопировать или отправить", "Open, copy or send"),
    "h_state": ("Состояние", "Status"),
    "h_wrong": ("Если что-то не так", "If something is wrong"),
    "h_tools": ("Настройки и инструменты", "Settings and tools"),
    "sec_recover": ("Восстановление и тесты", "Recovery and tests"),
    "sec_problems": ("Проверки и ошибки плагинов", "Checks and plugin errors"),
    "sec_problems_sub": ("Что искать, окно при ошибке плагина, уведомления", "What to look for, the plugin error popup, notifications"),
    "sec_reports_sub": ("Пакет для баг-репорта, отчёт по плагину, история, дамп, перенос настроек",
                        "Bug report bundle, plugin report, history, dump, settings transfer"),
    "h_search": ("Что искать", "What to look for"),
    "h_tell": ("Как сообщать", "How to tell you"),
    "h_check": ("Проверка", "Check"),
    "h_hist2": ("История", "History"),
    "h_dev": ("Для разработчиков", "For developers"),
    "h_data": ("Данные", "Data"),
    "bn_sub": ("Один файл для сложных случаев: отчёт, окружение, история зависаний, изменения плагинов, дамп и журнал. Обычно хватает отчёта с главной страницы",
               "One file for hard cases: report, environment, freeze history, plugin changes, dump and log. The report from the main page is usually enough"),
    "pop_title": ("Ошибка в плагине «{who}»", "Error in plugin “{who}”"),
    "pop_title_test": ("Пример: ошибка в плагине «{who}»", "Sample: error in plugin “{who}”"),
    "full_hint": ("«Копировать отчёт» копирует полный текст. «В Избранное» покажет, что уйдёт, и спросит подтверждение.",
                  "“Copy report” copies the full text. “To Saved” shows what will be sent and asks to confirm."),
    "rp_send": ("В Избранное", "To Saved"),

    # окно «Обнаруженные проблемы»
    "dlg_issues_n": ("Обнаруженные проблемы: {n}", "Detected problems: {n}"),
    "ir_intro": ("По каждой проблеме: что случилось, что это значит и что делать. «Копировать отчёт» кладёт в буфер полный текст со стеками и окружением: его можно показать автору плагина.",
                 "For each problem: what happened, what it means and what to do. “Copy report” puts the full text with stacks and environment on the clipboard, so you can show it to the plugin author."),
    "ir_copy": ("Копировать отчёт", "Copy report"),
    "ir_more": ("Ещё…", "More…"),
    "ir_close": ("Закрыть", "Close"),
    "ir_scan": ("Проверить сейчас", "Check now"),
    "ir_rescan": ("Проверить заново", "Check again"),
    "ir_clear": ("Очистить список", "Clear the list"),
    "ir_building": ("Собираю отчёт…", "Building the report…"),
    "ir_copied": ("Полный отчёт скопирован", "The full report was copied"),
    "ir_rest": ("…и ещё {n}: они есть в полном отчёте.", "…and {n} more: they are in the full report."),
    "ir_none_hint": ("Stall Doctor сам читает журнал и следит за плагинами. Если приложение ведёт себя странно, запустите проверку вручную.",
                     "Stall Doctor reads the log and watches plugins by itself. If the app misbehaves, run a check by hand."),
    "ir_more_title": ("Что ещё можно сделать", "More actions"),
    "ir_more_msg": ("«Проверить заново» перечитает журнал и плагины. «Очистить список» уберёт найденное: если проблема повторится, она появится снова.",
                    "“Check again” re-reads the log and plugins. “Clear the list” removes what was found; if a problem repeats it will show up again."),
    "ir_disable_q": ("Плагин «{who}» будет выключен. Включить его обратно можно в списке плагинов.",
                     "Plugin “{who}” will be switched off. You can switch it back on in the plugin list."),
    "ir_what": ("Что случилось", "What happened"),
    "ir_when_l": ("Когда", "When"),
    "ir_means": ("Что это значит", "What it means"),
    "ir_todo": ("Что делать", "What to do"),
    "ir_when": ("{t}, повторов: {n}", "{t}, repeats: {n}"),

    # полный отчёт о проблемах
    "ir_title": ("Stall Doctor {v} · отчёт о проблемах · {ts}", "Stall Doctor {v} · problem report · {ts}"),
    "ir_howto": ("Как читать: у каждой проблемы указано, что случилось, что это значит и что делать. Стеки и подробности идут под ней. Ссылки, @имена и длинные числа заменены метками.",
                 "How to read: each problem says what happened, what it means and what to do. Stacks and details follow. Links, @names and long numbers are replaced by markers."),
    "ir_head_n": ("ПРОБЛЕМЫ: {n}", "PROBLEMS: {n}"),
    "ir_plugin": ("Плагин: {p} v{v}, включён: {e}{f}", "Plugin: {p} v{v}, enabled: {e}{f}"),
    "ir_details": ("Подробности:", "Details:"),
    "ir_events": ("ЖУРНАЛ СОБЫТИЙ (последние 40)", "EVENT LOG (last 40)"),

    # что означает проблема (x_) и что с ней делать (a_)
    "x_crash": ("Приложение аварийно закрылось из-за необработанной ошибки (исключение Java). Telegram мог вылететь прямо во время работы.",
                "The app crashed because of an unhandled error (a Java exception). Telegram may have closed in the middle of use."),
    "a_crash": ("Стек места падения есть в полном отчёте: по нему видно, чей код вызвал ошибку.",
                "The stack of the crash is in the full report: it shows whose code caused the error."),
    "x_pytrace": ("В Python-коде плагина произошла необработанная ошибка. Приложение не упало, но часть функций плагина могла перестать работать.",
                  "An unhandled error happened in the plugin's Python code. The app did not crash, but some plugin features may have stopped working."),
    "a_pytrace": ("В полном отчёте есть файл, строка и текст ошибки: автору плагина этого достаточно, чтобы её исправить.",
                  "The full report has the file, line and error text: that is enough for the plugin author to fix it."),
    "x_plugin_log": ("Плагин записал ошибку в журнал приложения. Обычно это значит, что одна из его функций отработала неудачно.",
                     "The plugin wrote an error to the app log. Usually that means one of its functions failed."),
    "a_plugin_log": ("Если плагин работает нормально, можно не обращать внимания.", "If the plugin works fine you can ignore this."),
    "x_hook": ("Не удалось поставить или выполнить перехват (хук) метода Telegram. Функция плагина, которая на нём держится, не работает или работает с ошибками.",
               "A hook on a Telegram method could not be installed or run. The plugin feature that relies on it does not work or works with errors."),
    "a_hook": ("Чаще всего плагин не подходит к этой версии приложения: проверьте, нет ли обновления плагина или приложения.",
               "Most often the plugin does not fit this app version: check for an update of the plugin or the app."),
    "x_exit": ("Система завершила процесс приложения.", "The system terminated the app process."),
    "a_exit": ("Подробности есть в полном отчёте.", "Details are in the full report."),
    "x_exit_LOW_MEMORY": ("Android закрыл процесс Telegram, потому что системе не хватало оперативной памяти. Так бывает, когда телефон перегружен. Это не всегда вина плагина, но утечки памяти и потоков повышают риск.",
                          "Android closed the Telegram process because the system ran out of RAM. It happens when the phone is overloaded. It is not always a plugin's fault, but memory and thread leaks raise the risk."),
    "a_exit_LOW_MEMORY": ("Закройте лишние приложения и отключите ненужные плагины. Если закрытия повторяются и во время работы с Telegram, скопируйте полный отчёт: в нём рост памяти и потоков.",
                          "Close unneeded apps and switch off unneeded plugins. If it repeats while you are using Telegram, copy the full report: it has memory and thread growth."),
    "x_exit_bg": ("В тот момент Telegram работал в фоне, поэтому это, скорее всего, обычная чистка памяти Android, а не сбой плагина.",
                  "At that moment Telegram was in the background, so this is most likely Android's normal memory cleanup rather than a plugin failure."),
    "x_exit_fg": ("В тот момент Telegram был на экране или работал как служба, такое закрытие стоит разобрать.",
                  "At that moment Telegram was on screen or running as a service, so this exit is worth investigating."),
    "x_exit_CRASH": ("Процесс закрылся из-за краша.", "The process closed because of a crash."),
    "a_exit_CRASH": ("Стек падения есть в полном отчёте.", "The crash stack is in the full report."),
    "x_exit_CRASH_NATIVE": ("Процесс упал в нативном коде (C/C++), а не в Java или Python.", "The process crashed in native code (C/C++), not in Java or Python."),
    "a_exit_CRASH_NATIVE": ("Чаще виноваты сам Telegram или его библиотеки (видео, звонки). Если это началось после установки плагина, отключите его.",
                            "Most often Telegram itself or its libraries (video, calls) are to blame. If it started after installing a plugin, switch that plugin off."),
    "x_exit_ANR": ("Приложение не отвечало, и система закрыла его (ANR). Интерфейс не реагировал на нажатия.",
                   "The app did not respond and the system closed it (ANR). The interface ignored taps."),
    "a_exit_ANR": ("Стеки зависших потоков есть в полном отчёте.", "Stacks of the stuck threads are in the full report."),
    "x_exit_INITIALIZATION_FAILURE": ("Приложение не смогло запуститься.", "The app could not start."),
    "a_exit_INITIALIZATION_FAILURE": ("Отключите недавно установленные плагины и перезапустите приложение.", "Switch off recently installed plugins and restart the app."),
    "x_exit_EXCESSIVE_RESOURCE_USAGE": ("Android ограничил приложение за чрезмерное использование ресурсов, чаще всего процессора в фоне.",
                                        "Android penalised the app for excessive resource use, most often background CPU."),
    "a_exit_EXCESSIVE_RESOURCE_USAGE": ("Нагрузка по потокам есть в полном отчёте.", "Load by thread is in the full report."),
    "x_plugin_state": ("exteraGram сообщает, что плагин не загрузился, выключен из-за ошибки или не отвечает.",
                       "exteraGram reports that the plugin failed to load, was switched off because of an error or is not responding."),
    "a_plugin_state": ("Обновите или переустановите плагин. Если он не нужен, удалите его.", "Update or reinstall the plugin. If you do not need it, remove it."),
    "x_ui": ("Главный (интерфейсный) поток был заблокирован: приложение не реагировало на касания. Стек места, где это случилось, есть в полном отчёте.",
             "The main (UI) thread was blocked: the app did not react to taps. The stack of where it happened is in the full report."),
    "a_ui": ("Если назван плагин, значит он выполняет тяжёлую работу в главном потоке.", "If a plugin is named, it does heavy work on the main thread."),
    "x_memory": ("Память приложения (куча) почти заполнена. Рядом риск лагов и закрытия приложения.",
                 "The app's memory (heap) is almost full. Lags and a forced close are close."),
    "a_memory": ("Перезапустите приложение. Если повторяется, ищите плагин, который копит память: в полном отчёте есть рост памяти.",
                 "Restart the app. If it repeats, look for a plugin that hoards memory: the full report shows memory growth."),
    "x_memtrend": ("Занятая память приложения заметно растёт и не освобождается. Похоже на утечку.", "The app's used memory keeps growing and is not freed. It looks like a leak."),
    "a_memtrend": ("Перезапустите приложение. Если рост повторяется, отключайте плагины по очереди: в разделе «Восстановление и тесты» есть деление пополам.",
                   "Restart the app. If the growth repeats, switch plugins off one by one: the “Recovery and tests” section has bisecting."),
    "x_threads": ("Число потоков в приложении быстро выросло. Потоки копятся, когда код запускает их и не завершает.",
                  "The number of threads in the app grew fast. Threads pile up when code starts them and never ends them."),
    "a_threads": ("В полном отчёте потоки сгруппированы по именам: по ним видно, кто их создаёт.", "In the full report threads are grouped by name: that shows who creates them."),
    "x_pythreads": ("Плагин запускает всё новые Python-потоки и не завершает старые. Они копятся, занимают память и процессор, и в итоге приложение может тормозить или быть закрыто системой.",
                    "The plugin keeps starting new Python threads and does not finish the old ones. They pile up, use memory and CPU, and the app may lag or be closed by the system."),
    "a_pythreads": ("В полном отчёте есть имена потоков и строки кода, где они застряли: этого достаточно, чтобы найти утечку.",
                    "The full report has thread names and the code lines where they are stuck: that is enough to find the leak."),
    "x_fd": ("Приложение держит очень много открытых файлов и соединений. Когда лимит кончится, Android начнёт отказывать в новых.",
             "The app holds very many open files and connections. When the limit runs out Android will refuse new ones."),
    "a_fd": ("Перезапустите приложение. Если повторяется, отключайте плагины по очереди.", "Restart the app. If it repeats, switch plugins off one by one."),
    "x_cpu": ("Процесс долго сильно грузит процессор. Это разряжает батарею и вызывает лаги.", "The process keeps the CPU busy for long. It drains the battery and causes lag."),
    "a_cpu": ("Главные потоки перечислены в полном отчёте.", "The top threads are listed in the full report."),
    "x_jank": ("Интерфейс микрозависает: главный поток часто задерживается дольше 200 мс.", "The interface stutters: the main thread is often delayed for over 200 ms."),
    "a_jank": ("В полном отчёте видно, что выполнялось в момент задержки.", "The full report shows what was running at the time of the delay."),
    "x_storage": ("На устройстве мало свободного места. Telegram может не сохранять файлы и работать нестабильно.",
                  "The device is low on free space. Telegram may fail to save files and run unstably."),
    "a_storage": ("Освободите место или очистите кэш Telegram («Настройки» → «Данные и память»).", "Free some space or clear the Telegram cache (Settings → Data and Storage)."),
    "x_safemode": ("Движок плагинов работает в безопасном режиме: после сбоев часть плагинов отключена.",
                   "The plugin engine is in safe mode: some plugins were switched off after failures."),
    "a_safemode": ("Найдите плагин-виновник (раздел «Восстановление и тесты» → деление пополам) и включите остальные.",
                   "Find the culprit plugin (“Recovery and tests” → bisecting) and switch the others back on."),
    "x_notif": ("Уведомления могут приходить с задержкой или совсем не приходить: система ограничивает приложение.",
                "Notifications may arrive late or not at all: the system restricts the app."),
    "a_notif": ("Разрешите уведомления и работу в фоне для Telegram в настройках Android (батарея → «Без ограничений»).",
                "Allow notifications and background work for Telegram in Android settings (battery → “Unrestricted”)."),
    "a_who": ("Подозреваемый плагин: «{who}». Отключите его на время или обновите. Автору приложите полный отчёт (кнопка «Копировать отчёт»).",
              "Suspected plugin: “{who}”. Switch it off for a while or update it. Attach the full report for its author (the “Copy report” button)."),
    "a_np": ("Плагин не определён: по стеку и именам файлов найти его не удалось. В полном отчёте есть стек, окружение и список плагинов.",
             "The plugin could not be identified from the stack or file names. The full report has the stack, environment and plugin list."),
    "x_related": ("Возможно связано: {x}.", "Possibly related: {x}."),
    "xh_pref": ("Простыми словами:", "In plain words:"),
    "xh_zero": ("в коде произошло деление на ноль.", "the code divided by zero."),
    "xh_null": ("код обратился к значению, которого нет (null или None).", "the code used a value that does not exist (null or None)."),
    "xh_oom": ("не хватило памяти.", "out of memory."),
    "xh_stack": ("слишком глубокая цепочка вызовов, обычно это бесконечная рекурсия.", "the call chain is too deep, usually endless recursion."),
    "xh_conc": ("список или словарь изменили из двух потоков одновременно.", "a list or dict was changed from two threads at once."),
    "xh_compat": ("не найден метод, поле или модуль. Чаще всего плагин не подходит к этой версии приложения или написан с ошибкой.",
                  "a method, field or module was not found. Most often the plugin does not fit this app version or has a bug."),
    "xh_index": ("код обратился к элементу, которого нет в списке или словаре.", "the code asked for an item that is not in a list or dict."),
    "xh_type": ("код получил значение неподходящего вида (например, текст вместо числа).", "the code got a value of the wrong kind (for example text instead of a number)."),
    "xh_timeout": ("что-то не дождалось ответа вовремя.", "something did not get an answer in time."),
    "xh_perm": ("не хватило прав на действие.", "not enough permission for the action."),

    # подробности, которые теперь сохраняются в самой проблеме
    "d_pyth_series": ("Потоков плагина по проверкам: {x}", "Plugin threads by checks: {x}"),
    "d_pythread": ("{n}× поток «{name}»: код плагина {own}; сейчас в {last}", "{n}× thread “{name}”: plugin code {own}; now in {last}"),
    "d_exit_time": ("Время закрытия: {t}", "Closed at: {t}"),
    "d_exit_mem": ("Память процесса при закрытии: RSS {r} МБ, PSS {p} МБ", "Process memory at exit: RSS {r} MB, PSS {p} MB"),
    "d_exit_imp": ("Состояние приложения: {x}", "App state: {x}"),
    "imp_fg": ("на экране или служба переднего плана", "on screen or a foreground service"),
    "imp_vis": ("заметно пользователю", "visible to the user"),
    "imp_svc": ("фоновая служба", "background service"),
    "imp_cached": ("в фоне, в кэше процессов", "in the background, cached"),
})

THR_ITEMS = (["15 секунд", "30 секунд", "1 минута", "2 минуты"], ["15 seconds", "30 seconds", "1 minute", "2 minutes"])
STORM_ITEMS = (["Выключено", "8 в минуту", "12 в минуту", "20 в минуту"], ["Off", "8 per minute", "12 per minute", "20 per minute"])
OFFLINE_ITEMS = (["5 минут", "10 минут", "30 минут", "1 час"], ["5 minutes", "10 minutes", "30 minutes", "1 hour"])
ERR_INTERVAL_ITEMS = (["30 секунд", "1 минута", "3 минуты", "10 минут"], ["30 seconds", "1 minute", "3 minutes", "10 minutes"])
TTL_ITEMS = (["1 день", "3 дня", "7 дней", "Не забывать"], ["1 day", "3 days", "7 days", "Never"])
LANG_ITEMS = (["Как в приложении", "Русский", "English"], ["Same as the app", "Russian", "English"])


_LANG_CACHE = [0.0, 1]
_LANG_PREF = [None]   # функция, возвращающая выбор пользователя: 0 как в приложении, 1 русский, 2 English


def ui_lang():
    # вызов в Java дорог, а строки запрашиваются сотнями раз за круг; язык приложения не меняется каждую секунду
    try:
        pref = int(_LANG_PREF[0]()) if _LANG_PREF[0] else 0
    except Exception:
        pref = 0
    if pref in (1, 2):
        return 0 if pref == 1 else 1
    now = time.monotonic()
    if now - _LANG_CACHE[0] < 3:
        return _LANG_CACHE[1]
    try:
        code = str(LocaleController.getInstance().getCurrentLocale().getLanguage())
    except Exception:
        code = "en"
    _LANG_CACHE[0] = now
    _LANG_CACHE[1] = 0 if code in ("ru", "uk", "be", "kk") else 1
    return _LANG_CACHE[1]


def fmt_ts(t=None):
    return time.strftime("%H:%M:%S", time.localtime(t or time.time()))


def fmt_dur(sec):
    sec = int(max(sec, 0))
    return f"{sec // 3600}h {sec % 3600 // 60}m" if sec >= 3600 else f"{sec // 60}m {sec % 60}s"


def short(v, n=160):
    try:
        s = str(v)
    except Exception:
        s = "<?>"
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[:n] + "…"


def _g(obj, name):
    try:
        v = getattr(obj, name, None)
        if callable(v) and not isinstance(v, (bool, int, float, str)):
            try:
                v = v()
            except Exception as _e:
                _swallow(_e)
        return v
    except Exception:
        return None


class Probe:
    """Одна проверка «жив ли канал». Не копит запросы: пока предыдущая не вернулась, новая не уходит.
    Если ответ не пришёл за PROBE_LOST секунд, проба считается потерянной и уходит новая; «время ожидания»
    при этом не обнуляется, пока хоть какой-то ответ не вернётся (настоящее зависание не маскируется)."""

    def __init__(self, name):
        self.name = name
        self.sent = None
        self.since = None      # с какого момента нет ни одного ответа
        self.gen = 0
        self.lost = 0
        self.last_fire = 0.0
        self.last_latency = None
        self.last_error = None
        self.done_at = None

    def pending_for(self, now):
        return (now - self.since) if self.since else 0.0

    def reset(self):
        self.gen += 1
        self.sent = None
        self.since = None

    def fire(self, runner, now):
        if self.sent is not None:
            if now - self.sent < PROBE_LOST:
                return
            self.lost += 1
            self.last_error = f"no callback for {int(now - self.sent)}s"
            self.sent = None
        self.gen += 1
        gen = self.gen
        self.sent = now
        if self.since is None:
            self.since = now
        self.last_fire = now
        t0 = now

        def done(err=None):
            # любой ответ, даже запоздалый, доказывает, что канал жив
            self.last_latency = time.time() - t0
            self.last_error = err
            self.done_at = time.time()
            self.since = None
            if gen == self.gen:
                self.sent = None

        try:
            runner(done)
        except Exception as e:
            self.last_error = f"send failed: {e}"
            self.sent = None
            self.since = None


class StallDoctorPlugin(BasePlugin):
    _rlang = None

    # ---------- перевод ----------

    def t(self, key, **kw):
        idx = self._rlang if self._rlang is not None else ui_lang()
        try:
            return STR[key][idx].format(**kw)
        except Exception:
            return key

    def _report_lang_idx(self):
        try:
            sel = int(self.get_setting("report_lang", 0))
        except Exception:
            sel = 0
        return None if sel == 0 else (0 if sel == 1 else 1)

    # ---------- жизненный цикл ----------

    def _lang_changed(self, value=None):
        _LANG_CACHE[0] = 0.0
        self._rlang = None
        try:
            self.set_setting("ui_refresh", time.time(), reload_settings=True)
        except Exception as _e:
            _swallow(_e)

    def on_plugin_load(self):
        try:
            _LANG_PREF[0] = lambda: self.get_setting("ui_lang", 0)
            _LANG_CACHE[0] = 0.0
            self._rlang = None
            self.stop = threading.Event()
            self.events = collections.deque(maxlen=300)
            self.file_q = collections.deque(maxlen=500)   # строки журнала, ожидающие записи (из хуков файл не трогаем)
            self.journal_lock = threading.Lock()
            self.hook_last = {}
            self.gd_calls = collections.deque(maxlen=200)
            self.net_down_since = None
            self.last_offline = None
            self.hook_status = {}
            self.selfcheck = None
            self.hooks_cache = (0.0, {})
            self.lat = {}
            self.lat_seen = {}
            self.sim_active = False
            self.sim_cancel = threading.Event()
            self.last_auto_send = 0.0
            self.obs = None
            self.obs_id = 0
            self.obs_acc = 0
            self.last_net = None
            self.conn_since = None
            self.conn_hist = collections.deque(maxlen=60)
            self.proxy_cur = None
            self.proxy_alias = {}
            self.proxy_changes = collections.deque(maxlen=60)
            self.last_proxy_change = None
            self.ep_cur = None
            self.res_hist = collections.deque(maxlen=90)
            self.pyth_hist = collections.deque(maxlen=6)
            self.dead_parts = set()
            self.part_fails = {}
            self.jank = {"hist": [0] * 5, "n": 0, "worst": 0.0, "tops": collections.Counter(),
                         "plug": collections.Counter(), "recent": collections.deque(maxlen=200)}
            self.ops = {}
            self.op_pending = {}
            self.op_on = False
            self.history = collections.deque(maxlen=HIST_MAX)
            self.report_lock = threading.Lock()
            self.cond_since = {}
            self.episode = False
            self.healthy_ticks = 0
            self.suspicious = False
            self.diff_started = None
            self.upd_flag = None
            self.last_conn = None
            self.last_gd = None
            self.journal_lines = 0
            self.fcache = {}
            self.skip_until = 0.0
            self.last_notify = 0.0
            self.loaded_at = time.time()
            self.issues = {}
            try:
                self.cleared_at = float(self.get_setting("cleared_at", 0) or 0)
            except Exception:
                self.cleared_at = 0.0
            self.issue_lock = threading.Lock()
            self.health_lock = threading.Lock()
            self.last_log_ts = None
            self.log_edge = set()
            self.own_toggle = {}
            self.prog_last = None
            self.prog_at = time.time()
            self.ep_prev_end = 0.0
            self.ep_prev = None
            self.last_report_t = 0.0
            self.exit_done = False
            self.last_issue_notify = 0.0
            self.next_err = time.time() + 40
            self.last_popup = 0.0
            self.popup_plugin_ts = {}
            self.err_busy = threading.Lock()
            try:
                self.popped = set(json.loads(self.get_setting("popped_keys", "[]")))
            except Exception:
                self.popped = set()
            self.last_ui_capture = 0.0
            self.mem_high = 0
            self.mem = None
            self.tick_n = 0
            self.paused = False
            self.cpu_prev = None
            self.cpu_hist = collections.deque(maxlen=CPU_HIST)
            self.cpu_hot = 0
            self.next_cpu = time.time() + 30
            self.next_health = time.time() + HEALTH_FIRST
            try:
                self.notified = set(json.loads(self.get_setting("notified_keys", "[]")))
            except Exception:
                self.notified = set()
            self.state_names = dict(DEFAULT_STATE_NAMES)
            self.probes = {n: Probe(n) for n in ("ui", "plugins", "stage", "global", "ping")}
            self.base_dir = self._make_dir()
            self._load_journal()
            self._load_state_names()
            self.ev(self.t("e_started", v=__version__))
            if self.get_setting("trace_hooks", True):
                self._install_hooks()
            self._install_observer()
            self.op_on = bool(self.get_setting("op_timing", False))
            if self.op_on:
                for hn in OP_HOOKS:
                    try:
                        self.add_hook(hn, match_substring=True)
                    except Exception as e:
                        self.ev(f"op hook {hn}: {e}")
            threading.Thread(target=self._loop, name="StallDoctor", daemon=True).start()
            threading.Thread(target=self._bg_selfcheck, name="StallDoctorCheck", daemon=True).start()
            threading.Thread(target=self._safe, args=(self._recovery_eval,), name="StallDoctorRecovery", daemon=True).start()
            threading.Thread(target=self._jank_loop, name="StallDoctorJank", daemon=True).start()
            self._log(f"READY version={__version__}")
        except Exception as e:
            self._log(f"on_plugin_load error: {e}")

    def on_app_event(self, event_type):
        # В фоне плагин почти ничего не делает: свой вклад в нагрузку должен быть нулевым.
        try:
            n = getattr(event_type, "name", None)
            n = n() if callable(n) else n
            name = str(n if n else event_type).upper()
            if "PAUSE" in name or "STOP" in name:
                self.paused = True
            elif "START" in name or "RESUME" in name:
                self.paused = False
                for pr in self.probes.values():
                    pr.reset()
                self.cond_since.clear()
                self.skip_until = time.time() + 10
        except Exception as e:
            self._log(f"app_event: {e}")

    def on_plugin_unload(self):
        try:
            self.stop.set()
            self.sim_cancel.set()
            self._remove_observer()
            self.ev(self.t("e_unloaded"))
            self._flush_journal()
        except Exception as _e:
            _swallow(_e)

    def _log(self, text):
        # self.logger (тег plugin.stall_doctor) вместо устаревшего log()
        try:
            self.logger.info("[SD] " + str(text))
        except Exception:
            try:
                android_log(f"[SD] {text}")
            except Exception as _e:
                _swallow(_e)

    def _acc(self):
        try:
            return int(cu.get_selected_account())
        except Exception:
            return UserConfig.selectedAccount

    # ---------- файлы и журнал ----------

    def _make_dir(self):
        base = None
        try:
            if get_files_dir:
                base = get_files_dir()
        except Exception:
            base = None
        if not base:
            base = get_plugins_dir()
        path = os.path.join(str(base), "stall_doctor")
        os.makedirs(path, exist_ok=True)
        return path

    def _journal_path(self):
        return os.path.join(self.base_dir, "journal.log")

    def _load_journal(self):
        try:
            with open(self._journal_path(), "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
            self.journal_lines = len(lines)
            for line in lines[-150:]:
                self.events.append(line)
        except FileNotFoundError:
            pass
        except Exception as e:
            self._log(f"journal load error: {e}")

    def ev(self, text, defer=False):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {text}"
        try:
            self.events.append(line)
            if defer:
                self.file_q.append(line)   # запишет сторож, в хуке ввод-вывода нет
                return
            self._log(text)
            self._write_lines([line])
        except Exception as e:
            self._log(f"ev error: {e}")

    def _write_lines(self, lines):
        if not lines:
            return
        with self.journal_lock:
            with open(self._journal_path(), "a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            self.journal_lines += len(lines)
            if self.journal_lines > 600:
                with open(self._journal_path(), "r", encoding="utf-8", errors="replace") as f:
                    keep = f.read().splitlines()[-400:]
                with open(self._journal_path(), "w", encoding="utf-8") as f:
                    f.write("\n".join(keep) + "\n")
                self.journal_lines = len(keep)

    def _flush_journal(self):
        lines = []
        while self.file_q:
            try:
                lines.append(self.file_q.popleft())
            except IndexError:
                break
        try:
            self._write_lines(lines)
        except Exception as e:
            self._log(f"journal flush: {e}")

    def _hook_event(self, key, text):
        """Событие из Java-хука: не чаще раза в 2 с на ключ, остальное считаем."""
        now = time.time()
        st = self.hook_last.get(key) or [0.0, 0]
        if now - st[0] < 2.0:
            st[1] += 1
            self.hook_last[key] = st
            return
        extra = f" (+{st[1]})" if st[1] else ""
        self.hook_last[key] = [now, 0]
        self.ev(text + extra, defer=True)

    def _pick(self, key, values, default_idx):
        try:
            idx = int(self.get_setting(key, default_idx))
        except Exception:
            idx = default_idx
        return values[min(max(idx, 0), len(values) - 1)]

    def _gd_rate(self, now, window=60):
        return sum(1 for x in list(self.gd_calls) if now - x <= window)

    def _reports(self, short_only=False):
        try:
            suffix = ".short.txt" if short_only else ".txt"
            names = [n for n in os.listdir(self.base_dir)
                     if n.startswith("report_") and n.endswith(suffix) and (short_only or ".short" not in n)]
            names.sort()
            return [os.path.join(self.base_dir, n) for n in names]
        except Exception:
            return []

    def _latest(self, short_only=False):
        r = self._reports(short_only)
        return r[-1] if r else None

    def _bump(self, key):
        try:
            self.set_setting(key, int(self.get_setting(key, 0) or 0) + 1)
        except Exception as _e:
            _swallow(_e)

    # ---------- рефлексия и состояние ОС ----------

    def _load_state_names(self):
        try:
            cm_cls = jclass("org.telegram.tgnet.ConnectionsManager")
            for suffix in ("Connecting", "WaitingForNetwork", "Connected", "ConnectingToProxy", "Updating"):
                try:
                    self.state_names[int(getattr(cm_cls, "ConnectionState" + suffix))] = suffix
                except Exception as _e:
                    _swallow(_e)
        except Exception as e:
            self.ev(f"state names: {e}")

    def _field_map(self, key, class_name, pattern):
        if key in self.fcache:
            return self.fcache[key]
        res = {}
        try:
            cls = find_class(class_name)
            c = cls.getClass()
            if str(c.getName()) == "java.lang.Class":
                c = cls
            arr = c.getDeclaredFields()
            rx = re.compile(pattern, re.I)
            for i in range(len(arr)):
                f = arr[i]
                name = str(f.getName())
                if rx.search(name):
                    try:
                        f.setAccessible(True)
                    except Exception as _e:
                        _swallow(_e)
                    res[name] = f
        except Exception as e:
            self.ev(f"reflection {class_name}: {e}")
        self.fcache[key] = res
        return res

    def _read_fields(self, key, class_name, pattern, obj):
        out = {}
        for name, f in self._field_map(key, class_name, pattern).items():
            try:
                out[name] = f.get(obj)
            except Exception as e:
                out[name] = f"<error: {e}>"
        return out

    def _mc_fields(self, acc):
        return self._read_fields("mc", "org.telegram.messenger.MessagesController", MC_FIELDS_RE, get_messages_controller(acc))

    def _cm_fields(self, acc):
        return self._read_fields("cm", "org.telegram.tgnet.ConnectionsManager", CM_FIELDS_RE, get_connections_manager(acc))

    @staticmethod
    def _getting_difference(mc_vals):
        for k, v in mc_vals.items():
            kl = k.lower()
            if "gettingdifference" in kl and "channel" not in kl and isinstance(v, bool):
                return v
        return None

    def _os_online(self, acc):
        try:
            ctx = jclass("org.telegram.messenger.ApplicationLoader").applicationContext
            cmgr = ctx.getSystemService("connectivity")
            net = cmgr.getActiveNetwork()
            if net is None:
                return False
            caps = cmgr.getNetworkCapabilities(net)
            return bool(caps is not None and caps.hasCapability(12))  # NET_CAPABILITY_INTERNET
        except Exception as _e:
            _swallow(_e)
        try:
            return bool(get_connections_manager(acc).isNetworkOnline())
        except Exception:
            return None

    def _accounts_line(self, sel):
        parts = []
        try:
            total = int(UserConfig.MAX_ACCOUNT_COUNT)
        except Exception:
            total = 8
        for i in range(total):
            try:
                if not UserConfig.getInstance(i).isClientActivated():
                    continue
                st = self.state_names.get(int(get_connections_manager(i).getConnectionState()), "?")
                parts.append(f"{i}{'*' if i == sel else ''}: {st}")
            except Exception:
                continue
        return ", ".join(parts) if len(parts) > 1 else ""

    def nudge_now(self):
        """Просит клиент перепроверить сеть. Имена методов проверяются по месту, ничего не угадываем молча."""
        self._rlang = None
        acc = self._acc()
        cm = get_connections_manager(acc)
        before = self.state_names.get(int(cm.getConnectionState()), "?")
        called = []
        for name in ("resumeNetworkMaybe", "checkConnection"):
            fn = getattr(cm, name, None)
            if fn is None:
                continue
            try:
                fn()
                called.append(name)
            except Exception as e:
                self.ev(f"nudge {name}: {e}")
        if not called:
            run_on_ui_thread(lambda: BulletinHelper.show_error(self.t("nudge_none")))
            return
        self.stop.wait(5)
        after = self.state_names.get(int(cm.getConnectionState()), "?")
        x = ", ".join(called)
        self.ev(self.t("e_nudge", x=x, a=before, b=after))
        run_on_ui_thread(lambda: BulletinHelper.show_info(self.t("nudged", x=x, a=before, b=after)))

    def _proxy_enabled(self):
        try:
            sc = jclass("org.telegram.messenger.SharedConfig")
            try:
                return bool(sc.isProxyEnabled())
            except Exception:
                return sc.currentProxy is not None
        except Exception:
            return None

    # ---------- хуки: хронология getDifference ----------

    def _install_hooks(self):
        doctor = self
        try:
            class DiffHook(MethodHook):
                def before_hooked_method(self_h, param):
                    try:
                        doctor.diff_started = time.time()
                        doctor.gd_calls.append(doctor.diff_started)
                        doctor._hook_event("gd", "MessagesController.getDifference() called")
                    except Exception as _e:
                        _swallow(_e)

            mc = find_class("org.telegram.messenger.MessagesController")
            if mc:
                r = self.hook_all_methods(mc, "getDifference", DiffHook())
                n = len(r) if r is not None else 0
                self.hook_status["getDifference"] = (n > 0, f"{n} methods")
            else:
                self.hook_status["getDifference"] = (False, "class not found")
        except Exception as e:
            self.hook_status["getDifference"] = (False, str(e))
            self.ev(f"getDifference hook failed: {e}")
        try:
            class UpdHook(MethodHook):
                def before_hooked_method(self_h, param):
                    try:
                        v = bool(param.args[0])
                        doctor.upd_flag = (v, time.time())
                        doctor._hook_event("upd" + str(v), f"ConnectionsManager.setIsUpdating({v})")
                    except Exception as _e:
                        _swallow(_e)

            cm = find_class("org.telegram.tgnet.ConnectionsManager")
            if cm:
                r = self.hook_all_methods(cm, "setIsUpdating", UpdHook())
                n = len(r) if r is not None else 0
                self.hook_status["setIsUpdating"] = (n > 0, f"{n} methods")
            else:
                self.hook_status["setIsUpdating"] = (False, "class not found")
        except Exception as e:
            self.hook_status["setIsUpdating"] = (False, str(e))
            self.ev(f"setIsUpdating hook failed: {e}")

    # ---------- фоновый сторож ----------

    def _loop(self):
        last = time.time()
        while not self.stop.wait(TICK):
            now = time.time()
            lag = now - last - TICK
            last = now
            if lag > SLEEP_LAG:
                # телефон спал или процесс был заморожен: старые замеры недостоверны
                for p in self.probes.values():
                    p.reset()
                self.cond_since.clear()
                self.skip_until = now + 10
                self.ev(self.t("e_sleep", lag=int(lag)))
                continue
            if now >= self.next_cpu:
                self.next_cpu = now + CPU_EVERY
                self._part("cpu", self._cpu_sample, now)
            try:
                self._flush_journal()
            except Exception as _e:
                _swallow(_e)
            self._part("errwatch", self._err_watch_tick, now)
            if self.paused:
                try:
                    net = self._os_online(self._acc())
                    self.last_net = net
                    self._net_track(net, now)
                    self._part("proxy", self._proxy_track, now)
                except Exception as _e:
                    _swallow(_e)
                self.stop.wait(25)
                last = time.time()   # иначе следующий круг примет эту паузу за сон телефона
                continue
            try:
                self._tick(now)
            except Exception as e:
                self.ev(f"tick error: {e}")
            if now >= self.next_health:
                self.next_health = now + HEALTH_EVERY
                if self.get_setting("track_changes", True):
                    self._part("changes", self._plugin_snapshot_check)
                if self.get_setting("scan_logs", True):
                    threading.Thread(target=self._health_scan, args=(False,), name="StallDoctorScan", daemon=True).start()

    def _fire_probes(self, acc, now):
        P = self.probes
        P["ui"].fire(lambda d: run_on_ui_thread(d), now)
        for name, qname in (("plugins", "PLUGINS_QUEUE"), ("stage", "STAGE_QUEUE"), ("global", "GLOBAL_QUEUE")):
            q = getattr(cu, qname, None)
            if q is not None:
                P[name].fire(lambda d, q=q: run_on_queue(d, q), now)
        if not self.get_setting("ping", True):
            return
        every = PING_SUSPECT_EVERY if self.suspicious else PING_HEALTHY_EVERY
        if now - P["ping"].last_fire >= every:
            def run_ping(d):
                req = TLRPC.TL_updates_getState()

                def cb(resp, err):
                    d(short(getattr(err, "text", err), 60) if err else None)

                send_request(req, cb, account=acc)

            P["ping"].fire(run_ping, now)

    def _sample(self, acc, now):
        cm = get_connections_manager(acc)
        conn = int(cm.getConnectionState())
        net = self._os_online(acc)
        paused = False
        try:
            paused = bool(self._cm_fields(acc).get("appPaused"))
        except Exception as _e:
            _swallow(_e)
        gd = None
        mcv = None
        try:
            mcv = self._mc_fields(acc)
            gd = self._getting_difference(mcv)
        except Exception as e:
            self.ev(f"MessagesController fields: {e}")
        self._net_track(net, now)
        if net and self.last_net is False:
            self.probes["ping"].reset()     # сеть вернулась: запрос, ушедший в пустоту, не считаем зависанием
        self.last_net = net
        self._part("proxy", self._proxy_track, now)
        if conn != self.last_conn:
            self._conn_changed(conn, net, False)
        if gd != self.last_gd:
            self.ev(f"gettingDifference: {self.last_gd} → {gd}")
            self.last_gd = gd
        prog = self._progress_vals(mcv)
        if prog is not None:
            if prog != self.prog_last:
                self.prog_last = prog
                self.prog_at = now
        else:
            self.prog_last = None
        return {"t": now, "conn": conn, "net": net, "gd": gd, "paused": paused, "prog": prog}

    @staticmethod
    def _progress_vals(mcv):
        """Числовые счётчики догоняния обновлений (pts/qts/seq/date) или None, если прочитать их не удалось."""
        try:
            vals = tuple(sorted((k, v) for k, v in (mcv or {}).items()
                                if isinstance(v, (int, float)) and not isinstance(v, bool)
                                and re.search(r"lastPts|lastQts|lastSeq|lastDate|dialogsLoadedTill", k)))
            return vals or None
        except Exception as e:
            _swallow(e)
            return None

    def _net_track(self, net, now):
        if not self.get_setting("net_track", True):
            return
        if net is False and self.net_down_since is None:
            self.net_down_since = now
            self.ev(self.t("e_net_lost"))
        elif net and self.net_down_since is not None:
            dur = now - self.net_down_since
            self.net_down_since = None
            self.last_offline = (now, dur)
            if dur >= 30:
                self.ev(self.t("e_net_back", d=fmt_dur(dur)))

    def _tick(self, now):
        if not self.get_setting("monitor", True) or now < self.skip_until:
            return
        acc = self._acc()
        self._fire_probes(acc, now)
        s = self._sample(acc, now)
        ping_on = bool(self.get_setting("ping", True))
        self.history.append((s, {n: self._probe_text(n, now) for n in self.probes}))
        if self.get_setting("lat_profile", True):
            self._part("lat", self._lat_collect)
        for watcher in (self._watch_ui, self._watch_memory):
            self._part(watcher.__name__, watcher, now)

        hard = []
        for n, p in self.probes.items():
            if n == "ping" and (not ping_on or s["paused"] or s["net"] is False):
                continue
            limit = PING_LIMIT if n == "ping" else PROBE_LIMIT
            w = p.pending_for(now)
            if w >= limit:
                hard.append((n, w))

        soft = {}
        in_grace = (now - self.loaded_at) < GRACE_SEC
        if not s["paused"] and not in_grace:
            cname = self.state_names.get(s["conn"], str(s["conn"]))
            if cname in ("Updating", "Connecting", "ConnectingToProxy") or (cname == "WaitingForNetwork" and s["net"]):
                soft["conn:" + cname] = True
            if s["gd"]:
                soft["gettingDifference"] = True
        for k in list(self.cond_since):
            if k not in soft:
                del self.cond_since[k]
        for k in soft:
            self.cond_since.setdefault(k, now)

        try:
            idx = int(self.get_setting("threshold", 1))
        except Exception:
            idx = 1
        threshold = THRESHOLDS[min(max(idx, 0), len(THRESHOLDS) - 1)]
        # Долгое «Updating» / getDifference само по себе не зависание (после офлайна синк бывает долгим):
        # считаем его зависанием, только если pts/seq при этом не двигаются. Нет данных о pts: как раньше, по времени.
        advancing = s.get("prog") is not None and (now - self.prog_at) < threshold
        soft_long = [(k, now - v) for k, v in self.cond_since.items()
                     if now - v >= threshold and not (k in PROGRESS_KEYS and advancing)]

        self.suspicious = bool(hard or soft)
        stalled = bool(hard or soft_long)
        if stalled:
            self.healthy_ticks = 0
            if not self.episode:
                self.episode = True
                self._rlang = None
                parts = [self.t("d_problem", n=n, w=int(w)) for n, w in hard] + [self.t("d_cond", k=k, w=int(w)) for k, w in soft_long]
                reason = "; ".join(parts)
                if self.ep_prev and now - self.ep_prev_end < EP_MERGE_SEC:
                    # заминка вернулась сразу после конца прошлой: это продолжение, а не новый эпизод
                    self.ev(self.t("e_freeze_again", x=reason))
                    self.ep_cur = self.ep_prev
                    self._episode_update(self.ep_cur["t0"], open=True, dur=None)
                else:
                    self._bump("stat_episodes")
                    self.ev(self.t("e_freeze", x=reason))
                    self._episode_start(now, reason, s)
                self.ep_prev = None
                if now - self.last_report_t >= REPORT_GAP:
                    self.last_report_t = now
                    threading.Thread(target=self.make_report, args=(reason, False), name="StallDoctorReport", daemon=True).start()
                if (self.get_setting("auto_nudge", False) and s["net"]
                        and self.state_names.get(s["conn"]) == "WaitingForNetwork"):
                    threading.Thread(target=self.nudge_now, name="StallDoctorNudge", daemon=True).start()
        elif not self.suspicious:
            self.healthy_ticks += 1
            if self.episode and self.healthy_ticks >= 3:
                self.episode = False
                self.ev(self.t("e_recovered"))
                self._episode_end(now)

    def _probe_text(self, name, now):
        p = self.probes[name]
        limit = PING_LIMIT if name == "ping" else PROBE_LIMIT
        if name == "ping" and not self.get_setting("ping", True):
            return self.t("pr_off")
        w = p.pending_for(now)
        if w >= limit:
            return self.t("pr_stuck", w=int(w))
        if w > 0:
            return self.t("pr_wait", w=f"{w:.1f}")
        if p.last_latency is None:
            return self.t("pr_notyet")
        s = f"{p.last_latency * 1000:.0f} ms"
        if p.last_error:
            s += " (" + self.t("pr_err", e=p.last_error) + ")"
        if p.lost:
            s += " · " + self.t("pr_lost", n=p.lost)
        return s

    # ---------- снимок потоков ----------

    def _snap(self):
        me = threading.get_ident()
        own = {t.ident: t.name for t in threading.enumerate() if not isinstance(t, threading._DummyThread)}
        py = {}
        try:
            for tid, fr in sys._current_frames().items():
                if tid == me or str(own.get(tid, "")).startswith("StallDoctor"):
                    continue
                st = traceback.extract_stack(fr)
                py[tid] = {"name": own.get(tid), "foreign": tid not in own,
                           "frames": [(s.filename, s.lineno, s.name) for s in st]}
        except Exception as e:
            self.ev(f"python snapshot: {e}")
        java = {}
        try:
            it = jclass("java.lang.Thread").getAllStackTraces().entrySet().iterator()
            while it.hasNext():
                e = it.next()
                t = e.getKey()
                arr = e.getValue()
                name = str(t.getName())
                if name.startswith("StallDoctor"):
                    continue
                java[int(t.getId())] = {"name": name, "state": str(t.getState()), "obj": t,
                                        "frames": [str(arr[i]) for i in range(len(arr))]}
        except Exception as e:
            self.ev(f"java snapshot: {e}")
        return {"py": py, "java": java}

    @staticmethod
    def _java_relevant(info):
        if QUEUE_NAME_RE.search(info["name"]):
            return True
        return any(REL_RE.search(f) for f in info["frames"])

    @staticmethod
    def _java_idle(info):
        fr = info["frames"]
        if not fr or BENIGN_THREAD_RE.match(info["name"]):
            return True
        if "nativePollOnce" in fr[0]:
            return True
        return any("ThreadPoolExecutor.getTask" in f for f in fr)

    @staticmethod
    def _foreign_pkgs(frames):
        found = []
        for f in frames:
            cls = f.split("(")[0].rsplit(".", 1)[0]
            if not cls or cls.startswith(SAFE_PREFIXES):
                continue
            if len(cls.split(".")[0]) <= 2:
                continue  # обфусцированный код (a.b.c, WV.kw): по нему плагин не определить
            pkg = ".".join(cls.split(".")[:3])
            if pkg not in found:
                found.append(pkg)
        return found

    @staticmethod
    def _match_plugins(pkgs, ids, weak=None):
        """weak: если передан set, в него попадают плагины, найденные только по куску имени (менее надёжно)."""
        res = []
        for pkg in pkgs:
            segs = [x for x in pkg.lower().split(".") if len(x) >= 4 and x not in GENERIC_SEGS]
            for pid in ids:
                pl = pid.lower()
                norm = pl.replace("_", "").replace("-", "")
                toks = [x for x in re.split(r"[_\-]", pl) if len(x) >= 5 and x not in GENERIC_SEGS]
                for sg in segs:
                    if sg == pl or sg == norm or sg in toks:
                        if pid not in res:
                            res.append(pid)
                        if weak is not None and sg != pl and sg != norm:
                            weak.add(pid)
                        elif weak is not None:
                            weak.discard(pid)
                        break
        return res

    def _analyze_chains(self, a, b):
        lines, rescue, pkgs = [], [], []
        for tid, info in b["java"].items():
            prev = a["java"].get(tid)
            if not prev or self._java_idle(info):
                continue
            fr = info["frames"]
            if prev["frames"][:15] != fr[:15]:
                continue
            name = info["name"]
            waiting = any(any(m in f for m in WAIT_MARKERS) for f in fr[:8])
            storage_call = next((f for f in fr if "org.telegram.messenger.MessagesStorage." in f), None)
            foreign = self._foreign_pkgs(fr)
            for p in foreign:
                if p not in pkgs:
                    pkgs.append(p)
            m = re.search(r"MessagesStorage\.(\w+)", storage_call) if storage_call else None
            meth = m.group(1) if m else "?"
            if waiting and storage_call and name.startswith("storageQueue"):
                text = self.t("v_self", n=name, m=meth)
                if foreign:
                    text += self.t("v_self_from", pk=", ".join(foreign))
                lines.append(text)
                rescue.append(info)
            elif waiting and storage_call:
                lines.append(self.t("v_waitdb", n=name, m=meth))
            elif foreign:
                lines.append(self.t("v_foreign", n=name, pk=", ".join(foreign)))
        return lines, rescue, pkgs

    def _interrupt(self, infos):
        done = []
        for info in infos:
            try:
                info["obj"].interrupt()
                done.append(info["name"])
                self._bump("stat_rescued")
                self.ev(self.t("e_interrupt", n=info["name"]))
            except Exception as e:
                self.ev(f"interrupt {info['name']}: {e}")
        return done

    def rescue_now(self):
        self._rlang = None
        a = self._snap()
        self.stop.wait(3)
        b = self._snap()
        lines, rescue, pkgs = self._analyze_chains(a, b)
        if not rescue:
            run_on_ui_thread(lambda: BulletinHelper.show_info(self.t("rescue_none")))
            return
        done = self._interrupt(rescue)
        run_on_ui_thread(lambda: BulletinHelper.show_success(self.t("rescued", names=", ".join(done))))

    _pi_cache = (0.0, None)

    def _plugins_info(self):
        # список плагинов читается через мост Java (десятки вызовов); в одном круге проверок он нужен по нескольку раз
        now = time.monotonic()
        ts, cached = self._pi_cache
        if cached is not None and now - ts < 3:
            return [dict(x) for x in cached]
        res = self._plugins_info_read()
        if res:
            self._pi_cache = (now, [dict(x) for x in res])
        return res

    def _plugins_info_read(self):
        res = []
        try:
            pc = jclass("com.exteragram.messenger.plugins.PluginsController").getInstance()
            try:
                m = pc.getPlugins()
            except Exception:
                m = getattr(pc, "plugins", None)
            it = m.values().iterator()
            while it.hasNext():
                p = it.next()
                res.append({"id": _g(p, "id"), "version": _g(p, "version"), "enabled": _g(p, "isEnabled"),
                            "not_responding": _g(p, "isNotResponding"), "error": _g(p, "error")})
        except Exception as e:
            self.ev(f"plugin list: {e}")
        return res

    def _stem_map(self):
        """Имя файла плагина -> его __id__ (читаем первые КБ файла). Нужна, чтобы виновник из стека
        назывался настоящим id, а не именем файла, и один плагин не считался за два."""
        now = time.time()
        if now - _STEM_CACHE[0] < 60:
            return _STEM_CACHE[1]
        res = {}
        try:
            d = str(get_plugins_dir())
            for n in os.listdir(d):
                stem = n.rsplit(".", 1)[0]
                if not stem or stem.startswith("_"):
                    continue
                try:
                    with open(os.path.join(d, n), "r", encoding="utf-8", errors="ignore") as fh:
                        m = ID_RE.search(fh.read(16384))
                    res[stem] = m.group(1) if m else stem
                except Exception as e:
                    _swallow(e)
                    res[stem] = stem
        except Exception as e:
            _swallow(e)
        _STEM_CACHE[0] = now
        _STEM_CACHE[1] = res
        STEM_MAP.clear()
        STEM_MAP.update({k: v for k, v in res.items() if k != v})
        return res

    def _plugin_ids(self, infos=None):
        ids = set()
        try:
            for stem, pid in self._stem_map().items():
                if pid != "stall_doctor" and stem != "stall_doctor":
                    ids.add(pid)
        except Exception as e:
            _swallow(e)
        for p in (infos if infos is not None else self._plugins_info()):
            if p.get("id") and p["id"] != "stall_doctor":
                ids.add(str(p["id"]))
        return ids

    def _watchdog_dump(self):
        out = []
        try:
            pc = jclass("com.exteragram.messenger.plugins.PluginsController").getInstance()
            w = pc.getWatchdog()
            if w is None:
                return ["(none)"]
            arr = w.getClass().getDeclaredFields()
            for i in range(len(arr)):
                f = arr[i]
                try:
                    f.setAccessible(True)
                    if str(f.getName()) != "Companion":
                        out.append(f"{f.getName()} = {short(f.get(w), 120)}")
                except Exception as _e:
                    _swallow(_e)
        except Exception as e:
            out.append(f"(unavailable: {e})")
        return out

    # ---------- отчёт ----------

    def make_report(self, reason, manual):
        if not self.report_lock.acquire(False):
            if manual:
                run_on_ui_thread(lambda: BulletinHelper.show_info(self.t("report_busy")))
            return
        try:
            self._rlang = None
            snap_a = self._snap()
            self.stop.wait(RECHECK_SEC)
            snap_b = self._snap()
            self._rlang = self._report_lang_idx()
            text, verdict, short_text = self._compose(reason, manual, snap_a, snap_b)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self.base_dir, f"report_{stamp}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            with open(os.path.join(self.base_dir, f"report_{stamp}.short.txt"), "w", encoding="utf-8") as f:
                f.write(short_text)
            for old in self._reports()[:-REPORT_KEEP]:
                for p in (old, old[:-4] + ".short.txt"):
                    try:
                        os.remove(p)
                    except Exception as _e:
                        _swallow(_e)
            first = verdict[0] if verdict else "-"
            self.ev(self.t("e_saved", f=os.path.basename(path), v=short(first, 200)))
            ui_msg = "\n\n".join(verdict[:4])
            self._rlang = None
            if manual:
                run_on_ui_thread(lambda: self._report_dialog(self.t("dlg_result"), ui_msg))
            elif self.get_setting("notify", True) and time.time() - self.last_notify > NOTIFY_COOLDOWN:
                self.last_notify = time.time()
                run_on_ui_thread(lambda: BulletinHelper.show_error(self.t("freeze_notify")))
            if not manual and self.get_setting("auto_send", False) and time.time() - self.last_auto_send > 21600:
                self.last_auto_send = time.time()
                self._send_path(path, quiet=True)
        except Exception as e:
            self.ev(f"report error: {e}\n{traceback.format_exc()}")
        finally:
            self._rlang = None
            self.report_lock.release()

    def _compose(self, reason, manual, a, b):
        t = self.t
        now = time.time()
        acc = self._acc()
        infos = self._plugins_info()
        ids = self._plugin_ids(infos)

        stuck_java = []
        for tid, info in b["java"].items():
            prev = a["java"].get(tid)
            if prev and self._java_relevant(info) and not self._java_idle(info) and prev["frames"][:15] == info["frames"][:15]:
                stuck_java.append(info)
        stuck_py_foreign, stuck_py_own = [], []
        for tid, info in b["py"].items():
            prev = a["py"].get(tid)
            if prev and prev["frames"][-8:] == info["frames"][-8:]:
                (stuck_py_foreign if info["foreign"] else stuck_py_own).append(info)

        def mentioned(items):
            found = set()
            for info in items:
                files = " ".join(f for f, _, _ in info["frames"])
                for pid in ids:
                    if pid and pid in files:
                        found.add(pid)
            return sorted(found)

        suspects_hard = mentioned(stuck_py_foreign)
        suspects_soft = [p for p in mentioned(stuck_py_own) if p not in suspects_hard]
        verdict = self._diagnose(now, acc, stuck_java, suspects_hard, suspects_soft)
        chain_lines, rescue, pkgs = self._analyze_chains(a, b)
        weak_c = set()
        culprits = self._match_plugins(pkgs, ids, weak_c)
        self._note_culprits(sorted((set(culprits) - weak_c) | set(suspects_hard)))
        top = []
        if pkgs:
            who = ", ".join((c + " (?)") if c in weak_c else c for c in culprits) if culprits else t("v_unnamed")
            top.append(t("v_culprit", who=who, pk=", ".join(pkgs)))
            if culprits:
                top.append(t("v_advice", who=", ".join(culprits)))
            weak = (t("v_soft", x="").split("{")[0][:20], t("v_java")[:20])
            verdict = [v for v in verdict if not v.startswith(weak[0]) and not v.startswith(weak[1])]
        top.extend(chain_lines)
        if rescue and self.get_setting("auto_rescue", True):
            done = self._interrupt(rescue)
            if done:
                top.append(t("v_rescued", x=", ".join(done)))
        verdict = top + verdict
        rank = self._rank_suspects(now, culprits, suspects_hard, suspects_soft)
        if rank:
            verdict.insert(len(top), t("v_rank", x="; ".join(rank)))
        self._episode_note(verdict, list(set(culprits) | set(suspects_hard)))
        if verdict == [t("v_ok")] and self.issues:
            verdict = [t("v_issues", n=len(self.issues), x="; ".join(self._issues_text(3)))]

        cm_state = "?"
        net = proxy = paused = None
        try:
            cm = get_connections_manager(acc)
            cm_state = self.state_names.get(int(cm.getConnectionState()), str(cm.getConnectionState()))
            net = self._os_online(acc)
            paused = bool(self._cm_fields(acc).get("appPaused"))
        except Exception as _e:
            _swallow(_e)
        proxy = self._proxy_enabled()
        yn = lambda v: t("unknown") if v is None else (t("yes") if v else t("no"))

        build = ""
        try:
            build = str(jclass("org.telegram.messenger.BuildVars").BUILD_VERSION_STRING)
        except Exception as _e:
            _swallow(_e)
        head = [t("r_title", v=__version__, ts=time.strftime("%Y-%m-%d %H:%M:%S"), kind=t("r_manual") if manual else t("r_auto")),
                t("r_reason", x=reason), t("r_app", b=build or "?", a=acc)]
        probe_lines = []
        for n, key in (("ui", "p_ui"), ("plugins", "p_plugins"), ("stage", "p_stage"), ("global", "p_global"), ("ping", "p_ping")):
            probe_lines.append(f"{t(key)}: {self._probe_text(n, now)}")
        client_lines = [t("c_state", s=cm_state), t("c_net", n=yn(net)), t("c_proxy", p=yn(proxy)), t("c_paused", p=yn(paused))]
        if self.mem:
            client_lines.append(t("c_mem", u=self.mem[0] >> 20, m=self.mem[1] >> 20))
        acc_line = self._accounts_line(acc) if self.get_setting("report_accounts", True) else ""
        if acc_line:
            client_lines.append(t("c_accounts", x=acc_line))
        if not self.get_setting("net_track", True):
            pass
        elif self.net_down_since:
            client_lines.append(t("c_offline_now", d=fmt_dur(now - self.net_down_since)))
        elif self.last_offline:
            client_lines.append(t("c_offline_last", d=fmt_dur(self.last_offline[1]), a=int((now - self.last_offline[0]) // 60)))
        rate = self._gd_rate(now)
        if rate:
            client_lines.append(t("c_gdrate", n=rate))
        ph = self._proxy_changes_hour(now)
        if ph:
            client_lines.append(t("c_proxy_hist", n=ph))
        if self.dead_parts:
            client_lines.append(t("c_parts", x=", ".join(sorted(self.dead_parts))))

        out = list(head)

        def sec(key, **kw):
            out.append("")
            out.append("=" * 8 + " " + t(key, **kw) + " " + "=" * 8)

        sec("s_verdict")
        out.extend(f"{i}. {v}" for i, v in enumerate(verdict, 1))
        sec("s_probes")
        out.extend(probe_lines)
        sec("s_client")
        out.extend(client_lines)
        try:
            for k, v in sorted(self._cm_fields(acc).items()):
                if "proxy" not in k.lower():
                    out.append(f"ConnectionsManager.{k} = {short(v)}")
            for k, v in sorted(self._mc_fields(acc).items()):
                out.append(f"MessagesController.{k} = {short(v)}")
        except Exception as e:
            out.append(f"(unavailable: {e})")
        if self.diff_started:
            out.append(t("c_diff", t=fmt_ts(self.diff_started), a=int(now - self.diff_started)))
        if self.upd_flag:
            out.append(t("c_upd", v=self.upd_flag[0], t=fmt_ts(self.upd_flag[1]), a=int(now - self.upd_flag[1])))

        sec("s_env")
        out.extend(self._env_lines())

        sec("s_stuck", n=RECHECK_SEC)
        if not (stuck_java or stuck_py_foreign or stuck_py_own):
            out.append(t("none_stuck"))
        for info in stuck_java:
            out.append(f"[Java] {info['name']} ({info['state']})")
            out.extend("    " + f for f in info["frames"][:MAX_FRAMES])
        for info in stuck_py_foreign:
            out.append(t("hi_prio"))
            out.extend(f"    {f}:{ln} {fn}" for f, ln, fn in info["frames"][-12:])
        for info in stuck_py_own:
            out.append(t("low_prio", n=info["name"]))
            out.extend(f"    {f}:{ln} {fn}" for f, ln, fn in info["frames"][-6:])

        sec("s_events")
        out.extend(list(self.events)[-60:])
        sec("s_history")
        for s, pr in list(self.history)[-24:]:
            out.append(f"{fmt_ts(s['t'])} conn={self.state_names.get(s['conn'], s['conn'])} net={s['net']} gd={s['gd']} | "
                       + " ".join(f"{n}={v}" for n, v in pr.items()))

        sec("s_issues")
        out.extend(self._issues_text(25, detail=True) or [t("no_issues")])

        sec("s_cpu", n=max(1, len(self.cpu_hist) * CPU_EVERY // 60))
        out.extend(self._cpu_lines())

        sec("s_plugins")
        if not infos:
            out.append(t("pl_none", x=", ".join(sorted(ids))))
        for p in infos:
            flag = ""
            if p["not_responding"]:
                flag += f" [{t('pl_noresp')}]"
            if p["error"]:
                flag += f" [{t('pl_err')}: {short(p['error'], 100)}]"
            kc = int((self._jget("culprits", {}) or {}).get(str(p["id"]), 0))
            if kc >= 2:
                flag += t("pl_known", n=kc)
            out.append(f"{p['id']} v{p['version']} enabled={p['enabled']}{flag}")
        out.append(t("wd"))
        out.extend("  " + l for l in self._watchdog_dump())

        sec("s_changes")
        out.extend(self._changes_lines(14 * 86400, 20) or [t("chg_none")])
        sec("s_conn")
        out.extend(self._conn_lines())
        sec("s_self")
        out.extend(self._self_cost_lines())
        sec("s_jank")
        out.extend(self._jank_lines())
        sec("s_ops")
        out.extend(self._ops_lines())
        sec("s_lat")
        out.extend(self._lat_lines())
        sec("s_hooks")
        out.extend(self._hooks_lines())
        sec("s_selfcheck")
        out.extend(self._selfcheck_lines())

        sec("s_java")
        total = 0
        idle_names = []
        for tid, info in sorted(b["java"].items(), key=lambda kv: kv[1]["name"]):
            if not self._java_relevant(info):
                continue
            if self._java_idle(info):
                idle_names.append(info["name"])
                continue
            block = [f"-- {info['name']} [{info['state']}]"] + ["    " + f for f in info["frames"][:MAX_FRAMES]]
            total += sum(len(x) + 1 for x in block)
            if total > MAX_STACK_CHARS:
                out.append(t("trunc"))
                break
            out.extend(block)
        if idle_names:
            out.append(t("idle", n=len(idle_names), x=", ".join(idle_names)))

        sec("s_python")
        for tid, info in b["py"].items():
            kind = t("kind_java") if info["foreign"] else t("kind_py", n=info["name"])
            out.append(f"-- {kind}")
            out.extend(f"    {f}:{ln} {fn}" for f, ln, fn in info["frames"][-8:])

        short_lines = list(head) + ["", "== " + t("s_verdict") + " =="] + [f"{i}. {v}" for i, v in enumerate(verdict, 1)]
        short_lines += ["", "== " + t("s_probes") + " =="] + probe_lines + [""] + client_lines
        short_lines += ["", "== " + t("s_env") + " =="] + self._env_lines()
        short_lines += ["", "== " + t("s_issues") + " =="] + (self._issues_text(8) or [t("no_issues")])
        return "\n".join(out) + "\n", verdict, "\n".join(short_lines) + "\n"

    def _diagnose(self, now, acc, stuck_java, suspects_hard, suspects_soft):
        t = self.t
        P = self.probes

        def w(n):
            p = P.get(n)
            return p.pending_for(now) if p else 0.0

        ui, pq, st, gq = w("ui"), w("plugins"), w("stage"), w("global")
        ping = w("ping") if self.get_setting("ping", True) else 0.0
        cname = self.state_names.get(self.last_conn, str(self.last_conn))
        net = self.history[-1][0]["net"] if self.history else None
        out = []
        if ui >= PROBE_LIMIT:
            out.append(t("v_ui", w=int(ui)))
        if st >= PROBE_LIMIT:
            out.append(t("v_stage", w=int(st)))
        if pq >= PROBE_LIMIT and st < PROBE_LIMIT:
            out.append(t("v_plugins", w=int(pq)))
        if gq >= PROBE_LIMIT and st < PROBE_LIMIT:
            out.append(t("v_global", w=int(gq)))
        queues_ok = ui < PROBE_LIMIT and pq < PROBE_LIMIT and st < PROBE_LIMIT and gq < PROBE_LIMIT
        if queues_ok and ping >= PING_LIMIT and net is not False:
            px = t("v_proxy") if self._proxy_enabled() else ""
            out.append(t("v_net", w=int(ping), s=cname, px=px))
        err = P["ping"].last_error
        if queues_ok and err:
            out.append(t("v_srv_err", e=err))
        if queues_ok and ping < PING_LIMIT:
            gd_age = None
            if self.upd_flag and self.upd_flag[0]:
                gd_age = now - self.upd_flag[1]
            if cname == "Updating" or self.last_gd or (gd_age and gd_age > 30):
                x = t("v_gd_x", a=int(gd_age)) if gd_age and gd_age > 30 else ""
                out.append(t("v_gd", x=x))
            elif cname == "WaitingForNetwork" and net:
                out.append(t("v_waitnet"))
            elif cname in ("Connecting", "ConnectingToProxy"):
                out.append(t("v_conn", s=cname))
        if suspects_hard:
            out.append(t("v_hard", x=", ".join(suspects_hard)))
        if suspects_soft:
            out.append(t("v_soft", x=", ".join(suspects_soft)))
        if stuck_java and not suspects_hard:
            out.append(t("v_java"))
        rate = self._gd_rate(now)
        storm = self._pick("storm", STORM_VALUES, 2)
        if storm and rate >= storm:
            out.append(t("v_gdstorm", n=rate))
        if cname == "Updating" or self.last_gd or (storm and rate >= storm):
            hs = self._hook_suspects()
            if hs:
                out.append(t("v_hooklist", x=", ".join(f"{p} ({len(h)})" for p, h in sorted(hs.items()))))
        lo = self.last_offline if self.get_setting("net_track", True) else None
        if out and lo and lo[1] >= self._pick("offline", OFFLINE_VALUES, 1) and now - lo[0] < 1800:
            out.append(t("v_offline", d=fmt_dur(lo[1])))
        if out:
            recent = self._changes_lines(6 * 3600, 6)
            if recent:
                out.append(t("v_changes", x="; ".join(recent)))
            if self.last_proxy_change and now - self.last_proxy_change < 600:
                out.append(t("v_proxychg", d=fmt_dur(now - self.last_proxy_change)))
            ph = self._proxy_changes_hour(now)
            if ph >= 4:
                out.append(t("v_proxyflap", n=ph))
            pat = self._episode_pattern()
            if pat:
                out.append(pat)
            ac = self._jget("app_change", None)
            if isinstance(ac, dict) and ac.get("lost") and now - float(ac.get("t", 0)) < 3 * 86400:
                out.append(t("v_appchg", a=ac.get("a"), b=ac.get("b"), x=", ".join(ac["lost"][:8])))
            rv = self._recovery_verdict()
            if rv:
                out.append(rv)
        slow = self._lat_slow() if self.get_setting("lat_profile", True) else []
        if slow:
            out.append(t("v_slow", x="; ".join(slow)))
        osl = self._ops_slow()
        if osl:
            out.append(t("v_opslow", x="; ".join(osl)))
        rs = self._recovery_summary()
        if out and rs:
            out.append(t("v_recovery", x=rs))
        if not out:
            out.append(t("v_ok"))
        return out

    # ---------- здоровье системы: журнал, прошлые сбои, плагины, UI, память ----------

    @staticmethod
    def _redact(text, limit=220):
        text = re.sub(r"https?://\S+", "<url>", str(text))
        text = re.sub(r"@\w{3,}", "@<user>", text)
        text = re.sub(r"\+?\d{7,}", "<num>", text)
        return text if len(text) <= limit else text[:limit] + "…"

    @staticmethod
    def _row_epoch(ts):
        now = time.time()
        year = time.localtime(now).tm_year
        for y in (year, year - 1):          # второй вариант: строка из декабря, читаем в январе; и 29 февраля
            try:
                ep = time.mktime(time.strptime(f"{y}-{ts[:14]}", "%Y-%m-%d %H:%M:%S"))
            except Exception:
                continue
            if ep > now + 86400:
                continue
            try:
                ep += int(ts[15:18]) / 1000.0
            except Exception as _e:
                _swallow(_e)
            return ep
        return now

    @staticmethod
    def _plugins_from_paths(text, ids):
        found = []
        for m in PLUGIN_PATH_RE.finditer(text):
            pid = STEM_MAP.get(m.group(1), m.group(1))
            if pid in ids and pid not in found:
                found.append(pid)
        return found

    def _issue_ttl(self):
        try:
            return ISSUE_TTL[min(max(int(self.get_setting("issue_ttl", 1)), 0), len(ISSUE_TTL) - 1)]
        except Exception:
            return ISSUE_TTL[1]

    def _issue_expired(self, epoch):
        ttl = self._issue_ttl()
        return bool(ttl) and epoch < time.time() - ttl

    def _prune_issues(self):
        with self.issue_lock:
            for k in [k for k, v in self.issues.items() if self._issue_expired(v["epoch"])]:
                del self.issues[k]

    def _forget_issues(self):
        """Очищает список и запоминает момент: события старше него больше не вернутся (журнал и история Android перечитываются)."""
        self.cleared_at = time.time()
        try:
            self.set_setting("cleared_at", str(self.cleared_at))
        except Exception as _e:
            _swallow(_e)
        with self.issue_lock:
            self.issues.clear()

    def _add_issue(self, kind, plugins, summary, detail, epoch, pkgs=(), unique=False, extra=None):
        if epoch <= getattr(self, "cleared_at", 0) or self._issue_expired(epoch):
            return
        if plugins and any(str(p).startswith("sdchk") for p in plugins):
            return      # строки, которые сам плагин пишет при проверке журнала
        plug = ", ".join(plugins) if plugins else ""
        key = (kind, plug, re.sub(r"\d+", "#", summary)[:120])
        created = False
        with self.issue_lock:
            it = self.issues.get(key)
            if it:
                if unique:
                    return
                it["count"] += 1
                it["epoch"] = max(it["epoch"], epoch)
            else:
                created = True
                self.issues[key] = {"key": key, "kind": kind, "plugin": plug, "summary": summary, "detail": list(detail),
                                    "pkgs": list(pkgs), "count": 1, "epoch": epoch, "extra": dict(extra or {})}
                if len(self.issues) > 200:
                    oldest = min(self.issues.values(), key=lambda v: v["epoch"])
                    self.issues.pop(oldest["key"], None)
        if created and plugins and kind in ("crash", "ui", "pytrace"):
            self._note_culprits(list(plugins))

    def _read_logcat(self, n=None):
        cmd = ["logcat", "-d", "-v", "threadtime", "-t", str(n or LOG_LINES)]
        try:
            import subprocess
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=20)
            return r.stdout.splitlines()
        except Exception as e:
            self.ev(f"logcat via subprocess: {e}")
        try:
            proc = jclass("java.lang.Runtime").getRuntime().exec(cmd)
            rd = jclass("java.io.BufferedReader")(jclass("java.io.InputStreamReader")(proc.getInputStream()))
            lines = []
            while len(lines) < (n or LOG_LINES) + 200:
                line = rd.readLine()
                if line is None:
                    break
                lines.append(str(line))
            rd.close()
            return lines
        except Exception as e:
            self.ev(f"logcat via Runtime: {e}")
        return []

    def _parse_log(self, lines, ids, sink=None):
        add = sink or self._add_issue   # sink: проверка журнала собирает находки, не трогая настоящие проблемы и курсор
        rows = []
        for ln in lines:
            m = LOG_RE.match(ln)
            rows.append(m.groups() if m else None)
        # время каждой строки в секундах (с миллисекундами); курсор хранится числом, а не строкой «ММ-ДД ЧЧ:ММ»,
        # иначе после Нового года или перевода часов все новые строки выглядели бы «старыми»
        ecache = {}
        eps = []
        for r in rows:
            if not r:
                eps.append(None)
                continue
            k = r[0][:14]
            base = ecache.get(k)
            if base is None:
                base = ecache[k] = self._row_epoch(k + ".000")
            try:
                eps.append(base + int(r[0][15:18]) / 1000.0)
            except Exception:
                eps.append(base)
        cutoff = None if sink else self.last_log_ts
        edge = set() if sink else self.log_edge
        valid = [e for e in eps if e is not None]
        newest = max(valid) if valid else None
        if cutoff is not None and newest is not None and newest < cutoff - LOG_CLOCK_BACK:
            # время в журнале пошло назад (перевод часов): старый курсор больше не годится, берём новый и ничего не разбираем
            self.ev(self.t("e_log_clock", d=fmt_dur(cutoff - newest)))
            self.last_log_ts = newest
            self.log_edge = {(r[0], r[1], r[2], r[5][:60]) for r, e in zip(rows, eps) if r and e == newest}
            return
        if cutoff is not None and newest is not None and newest < cutoff:
            newest = cutoff
        n = len(rows)
        i = 0
        while i < n:
            row = rows[i]
            i += 1
            if not row:
                continue
            ts, pid, tid, lvl, tag, msg = row
            ep = eps[i - 1]
            if cutoff is not None:
                if ep < cutoff:
                    continue
                if ep == cutoff and (ts, pid, tid, msg[:60]) in edge:
                    continue
            if lvl in "EF" and "FATAL EXCEPTION" in msg:
                block, j = [], i
                while j < n and len(block) < 45:
                    r = rows[j]
                    if not r or r[1] != pid or r[4] != tag:
                        break
                    block.append(r[5])
                    j += 1
                i = j
                exc = next((b for b in block if re.search(r"(Exception|Error)\b", b) and not b.lstrip().startswith("at ")),
                           block[0] if block else "FATAL EXCEPTION")
                pk = self._foreign_pkgs([b.strip()[3:] for b in block if b.lstrip().startswith("at ")])
                wk = set()
                plug = self._match_plugins(pk, ids, wk)
                add("crash", plug, self._redact(exc), [self._redact(x) for x in block[:12]], ep, pk,
                                extra={"weak": sorted(wk)} if wk else None)
            elif "Traceback (most recent call last)" in msg:
                block, j = [msg], i
                while j < n and len(block) < 30:
                    r = rows[j]
                    if not r or r[1] != pid or r[2] != tid or r[4] != tag:
                        break
                    block.append(r[5])
                    j += 1
                i = j
                plug = self._plugins_from_paths("\n".join(block), ids)
                add("pytrace", plug, self._redact(block[-1].strip()), [self._redact(x) for x in block[-10:]], ep)
            elif lvl in "EF" and tag.startswith("plugin."):
                add("plugin_log", [tag[7:].split(".")[0]], self._redact(msg, 160), [], ep)
            elif lvl in "EW" and tag in ("LSPosed", "LSPosed-Bridge", "Xposed", "XposedBridge") \
                    and ("xception" in msg or ("hook" in msg.lower() and "fail" in msg.lower())):
                add("hook", [p for p in ids if p in msg], self._redact(msg, 160), [], ep)
        if newest is not None and sink is None:
            keep = {(r[0], r[1], r[2], r[5][:60]) for r, e in zip(rows, eps) if r and e == newest}
            self.log_edge = (edge | keep) if newest == cutoff else keep
            self.last_log_ts = newest

    def _anr_frames(self, info):
        frames = []
        try:
            stream = info.getTraceInputStream()
            if stream is None:
                return frames
            rd = jclass("java.io.BufferedReader")(jclass("java.io.InputStreamReader")(stream))
            cur, count = None, 0
            while count < 8000:
                line = rd.readLine()
                if line is None:
                    break
                count += 1
                line = str(line)
                m = re.match(r'^"(.+?)" ', line)
                if m:
                    cur = m.group(1)
                    continue
                if cur and (cur == "main" or cur.startswith(("storageQueue", "stageQueue", "pluginsQueue", "globalQueue"))):
                    mm = re.match(r"^\s+at ([\w$.<>]+)\(", line)
                    if mm:
                        frames.append(mm.group(0).strip()[3:])
            rd.close()
        except Exception as e:
            self.ev(f"ANR trace: {e}")
        return frames

    def _exit_issues(self, ids):
        try:
            ctx = jclass("org.telegram.messenger.ApplicationLoader").applicationContext
            am = ctx.getSystemService("activity")
            lst = am.getHistoricalProcessExitReasons(str(ctx.getPackageName()), 0, 8)
        except Exception as e:
            self.ev(f"exit info: {e}")
            return
        now = time.time()
        for i in range(lst.size()):
            try:
                info = lst.get(i)
                reason = int(info.getReason())
                ts = int(info.getTimestamp()) / 1000.0
                if reason not in EXIT_NAMES or now - ts > 3 * 86400:
                    continue
                desc = str(info.getDescription() or "")
                frames = self._anr_frames(info) if reason == 6 else []
                pk = self._foreign_pkgs(frames)
                plug = self._match_plugins(pk, ids)
                detail = [self._redact(f) for f in frames[:12]]
                if reason == 9:
                    detail = [self.t("i_cpu_exit")] + self._cpu_lines(5)
                lines, extra = self._exit_facts(info, ts)
                if reason == 3 and extra.get("bg") and self.get_setting("hide_bg_lowmem", True):
                    continue
                self._add_issue("exit", plug, self._redact(f"{EXIT_NAMES[reason]}: {desc}", 140), lines + detail, ts, pk,
                                unique=True, extra=extra)
            except Exception as e:
                self.ev(f"exit info item: {e}")

    def _exit_facts(self, info, ts):
        """Что известно о закрытии процесса: когда, сколько памяти занимал, был ли он на экране."""
        t = self.t
        lines, extra = [t("d_exit_time", t=time.strftime("%m-%d %H:%M:%S", time.localtime(ts)))], {}
        try:
            rss, pss = int(info.getRss()), int(info.getPss())
            if rss or pss:
                lines.append(t("d_exit_mem", r=rss >> 10, p=pss >> 10))
        except Exception as _e:
            _swallow(_e)
        try:
            imp = int(info.getImportance())
            extra["bg"] = imp >= 300
            key = "imp_fg" if imp <= 125 else ("imp_vis" if imp <= 270 else ("imp_svc" if imp < 400 else "imp_cached"))
            lines.append(t("d_exit_imp", x=f"{t(key)} ({imp})"))
        except Exception as _e:
            _swallow(_e)
        return lines, extra

    def _plugin_state_issues(self):
        with self.issue_lock:
            for k in [k for k, v in self.issues.items() if v["kind"] == "plugin_state"]:
                del self.issues[k]
        for p in self._plugins_info():
            if p.get("id") == "stall_doctor":
                continue
            if not p.get("enabled"):
                if p.get("error"):
                    self._add_issue("plugin_state", [str(p["id"])], self.t("i_state_disabled_err", e=short(p["error"], 120)), [], time.time())
                continue
            if p.get("error"):
                self._add_issue("plugin_state", [str(p["id"])], self.t("i_state_err", e=short(p["error"], 120)), [], time.time())
            elif p.get("not_responding"):
                self._add_issue("plugin_state", [str(p["id"])], self.t("i_state_noresp"), [], time.time())

    def _watch_ui(self, now):
        w = self.probes["ui"].pending_for(now)
        if w < UI_BLOCK or now - self.last_ui_capture < 60:
            return
        self.last_ui_capture = now
        th = jclass("android.os.Looper").getMainLooper().getThread()
        arr = th.getStackTrace()
        frames = [str(arr[i]) for i in range(len(arr))]
        pk = self._foreign_pkgs(frames)
        ids = self._plugin_ids()
        wk = set()
        plug = self._match_plugins(pk, ids, wk)
        if not plug and not pk:
            snap = self._snap()["py"]
            files = " ".join(f for info in snap.values() if info["foreign"] for f, _, _ in info["frames"])
            plug = self._plugins_from_paths(files, ids)
        self._add_issue("ui", plug, self.t("i_ui", w=int(w)), frames[:14], now, pk,
                        extra={"weak": sorted(wk)} if wk else None)

    def _watch_memory(self, now):
        self.tick_n += 1
        if self.tick_n % 6:
            return
        rt = jclass("java.lang.Runtime").getRuntime()
        mx = int(rt.maxMemory())
        used = int(rt.totalMemory()) - int(rt.freeMemory())
        self.mem = (used, mx)
        ratio = used / mx if mx else 0
        self.mem_high = self.mem_high + 1 if ratio > 0.92 else (0 if self.mem_high >= 0 else self.mem_high + 1)
        if self.mem_high >= 4:
            self.mem_high = -8
            self._add_issue("memory", [], self.t("i_mem", p=int(ratio * 100), u=used >> 20, m=mx >> 20), [], now)

    def _issues_text(self, limit=12, detail=False):
        with self.issue_lock:
            items = sorted(self.issues.values(), key=lambda v: (v["plugin"] == "", v["kind"] not in ("crash", "exit", "ui", "pytrace"), -v["count"], -v["epoch"]))
        lines = []
        for it in items[:limit]:
            wk = (it.get("extra") or {}).get("weak") or []
            who = ", ".join((p + " (?)") if p in wk else p for p in it["plugin"].split(", ")) if it["plugin"] else self.t("who_unknown")
            what = f"{self.t('k_' + it['kind'])}: {short(it['summary'], 110)}"
            lines.append(self.t("i_line", who=who, what=what, n=it["count"], t=time.strftime("%m-%d %H:%M", time.localtime(it["epoch"]))))
            if detail:
                lines.extend("    " + d for d in it["detail"][:8])
        return lines

    def _notify_new_issues(self):
        if not self.get_setting("notify_issues", True):
            return
        now = time.time()
        if now - self.last_issue_notify < NOTIFY_COOLDOWN:
            return
        with self.issue_lock:
            items = list(self.issues.values())
        for it in items:
            if not it["plugin"] or now - it["epoch"] > NOTIFY_RECENT:
                continue
            if it["kind"] not in ("crash", "exit", "ui", "pytrace") and it["count"] < NOTIFY_ISSUE_MIN:
                continue
            nid = hashlib.md5(f"{it['key']!r}|{time.strftime('%Y%m%d', time.localtime(it['epoch']))}".encode("utf-8")).hexdigest()[:10]
            if nid in self.notified:
                continue
            if self.get_setting("err_popup", True) and self._err_nid(it) in self.popped:
                continue
            self.notified.add(nid)
            try:
                self.set_setting("notified_keys", json.dumps(sorted(self.notified)[-60:]))
            except Exception as _e:
                _swallow(_e)
            self.last_issue_notify = now
            msg = self.t("n_issue", who=it["plugin"], what=f"{self.t('k_' + it['kind'])}")
            run_on_ui_thread(lambda: BulletinHelper.show_error(msg))
            return

    # ---------- ошибки плагинов: слежение и окно с вариантами ----------

    @staticmethod
    def _err_nid(it):
        return hashlib.md5(repr(it["key"]).encode("utf-8")).hexdigest()[:10]

    def _err_ignored(self, pid):
        raw = str(self.get_setting("err_ignore", "") or "")
        ign = {x.strip().lower() for x in raw.replace(";", ",").split(",") if x.strip()}
        return pid.lower() in ign

    def _err_watch_tick(self, now):
        if not self.get_setting("err_watch", True) or now < self.next_err or self.stop.is_set():
            return
        try:
            idx = int(self.get_setting("err_interval", 1))
        except Exception:
            idx = 1
        self.next_err = now + ERR_INTERVALS[min(max(idx, 0), len(ERR_INTERVALS) - 1)]
        threading.Thread(target=self._safe, args=(self._err_scan_worker,), name="StallDoctorErrors", daemon=True).start()

    def _err_scan_worker(self):
        if not self.err_busy.acquire(False):
            return
        try:
            if self.health_lock.acquire(False):
                try:
                    self._rlang = None
                    self._parse_log(self._read_logcat(ERR_LOG_LINES), self._plugin_ids())
                    self._plugin_state_issues()
                finally:
                    self.health_lock.release()
            self._err_popup_next()
        finally:
            self.err_busy.release()

    def _err_popup_next(self):
        now = time.time()
        if not self.get_setting("err_popup", True) or now - self.last_popup < POPUP_COOLDOWN:
            return None
        try:
            level = int(self.get_setting("err_level", 0))
        except Exception:
            level = 0
        kinds = ERR_SERIOUS if level == 1 else tuple(ERR_PRIO)
        with self.issue_lock:
            items = list(self.issues.values())
        best = None
        for it in items:
            if it["kind"] not in kinds or not it["plugin"]:
                continue
            plug = [x for x in it["plugin"].split(", ") if x and x != "stall_doctor" and not self._err_ignored(x)]
            if not plug:
                continue
            old_ok = it["kind"] in ("crash", "exit")
            if now - it["epoch"] > ERR_RECENT or (not old_ok and it["epoch"] < self.loaded_at - 60):
                continue
            if self._err_nid(it) in self.popped or now - self.popup_plugin_ts.get(plug[0], 0) < POPUP_PLUGIN_COOLDOWN:
                continue
            rank = (ERR_PRIO.get(it["kind"], 9), -it["epoch"])
            if best is None or rank < best[0]:
                best = (rank, it, plug)
        if best:
            run_on_ui_thread(lambda: self._popup_show(best[1], best[2]))
            return best[1]
        return None

    def _err_where(self, it):
        for line in reversed(it.get("detail") or []):
            m = re.search(r'File "([^"]+)", line (\d+), in (\S+)', line)
            if m and ("plugins" in m.group(1) or it["plugin"].split(", ")[0] in m.group(1)):
                return f"{os.path.basename(m.group(1))}:{m.group(2)} ({m.group(3)})"
        return ""

    def _error_text(self, it, plug):
        t = self.t
        parts = [t("ep_what") + ": " + t("ep_x_" + it["kind"]) if ("ep_x_" + it["kind"]) in STR else t("ep_what"),
                 "", t("ep_err") + ": " + short(it["summary"], 220)]
        where = self._err_where(it)
        if where:
            parts.append(t("ep_where") + ": " + where)
        parts.append(t("ep_count", n=it["count"], t=time.strftime("%H:%M", time.localtime(it["epoch"]))))
        parts += ["", t("ep_advice")]
        return "\n".join(parts)

    def _popup_show(self, it, plug, test=False):
        try:
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return False
            self._rlang = None
            who = plug[0]
            if not test:
                self.popped.add(self._err_nid(it))
                self.last_popup = time.time()
                self.popup_plugin_ts[who] = time.time()
                try:
                    self.set_setting("popped_keys", json.dumps(sorted(self.popped)[-80:]))
                except Exception as _e:
                    _swallow(_e)
                self.ev(f"error popup: {who} {it['kind']}")
            text = self._error_text(it, plug)
            if test:
                text += "\n\n" + self.t("ep_test_note")
            b = AlertDialogBuilder(act)
            b.set_title(self.t("pop_title_test" if test else "pop_title", who=who))
            b.set_message(text[:3500])
            b.set_positive_button(self.t("ep_disable", who=short(who, 24)), lambda bld, w: (bld.dismiss(), self._err_disable(who, test)))
            b.set_negative_button(self.t("copy"), lambda bld, w: (copy_to_clipboard(f"{who}\n{text}"), bld.dismiss()))
            b.set_neutral_button(self.t("ep_more"), lambda bld, w: (bld.dismiss(), self._err_more(it, plug, test)))
            b.show()
            return True
        except Exception as e:
            self.ev(f"error popup: {e}")
            return False

    def _err_disable(self, pid, test=False):
        if test:
            BulletinHelper.show_info(self.t("ep_test_note"))
            return

        def work():
            ok = self._plugin_set_enabled(pid, False)
            self._rlang = None
            run_on_ui_thread(lambda: (BulletinHelper.show_success if ok else BulletinHelper.show_error)(
                self.t("ep_disabled" if ok else "ep_disable_fail", who=pid)))
            if ok:
                self.ev(f"error popup: disabled {pid}")
        threading.Thread(target=self._safe, args=(work,), name="StallDoctorDisable", daemon=True).start()

    def _err_ignore_add(self, pid):
        raw = [x.strip() for x in str(self.get_setting("err_ignore", "") or "").replace(";", ",").split(",") if x.strip()]
        if pid.lower() not in [x.lower() for x in raw]:
            raw.append(pid)
        self.set_setting("err_ignore", ", ".join(raw))
        self._rlang = None
        BulletinHelper.show_info(self.t("ep_ignored", who=pid))

    def _err_more(self, it, plug, test=False):
        try:
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return
            self._rlang = None
            who = plug[0]
            b = AlertDialogBuilder(act)
            b.set_title(self.t("ep_more_title"))
            b.set_message(self.t("ep_more_msg"))
            b.set_positive_button(self.t("ep_reload"), lambda bld, w: (bld.dismiss(), self._act_recover("reload")))
            b.set_negative_button(self.t("ep_ignore", who=short(who, 24)),
                                  lambda bld, w: (bld.dismiss(), BulletinHelper.show_info(self.t("ep_test_note")) if test else self._err_ignore_add(who)))
            b.set_neutral_button(self.t("ep_details"), lambda bld, w: (bld.dismiss(), self._act_issues()))
            b.show()
        except Exception as e:
            self.ev(f"error more: {e}")

    def _act_err_test(self):
        self._rlang = None
        it = {"key": ("pytrace", "test_plugin", "TypeError: demo"), "kind": "pytrace", "plugin": "test_plugin", "count": 3,
              "summary": "TypeError: 'NoneType' object is not subscriptable", "epoch": time.time(), "pkgs": [],
              "detail": ['Traceback (most recent call last):', '  File "/data/plugins/test_plugin.py", line 42, in on_message',
                         '    x = data["id"]', "TypeError: 'NoneType' object is not subscriptable"]}
        self._popup_show(it, ["test_plugin"], test=True)

    def _act_err_by_plugin(self):
        self._rlang = None
        with self.issue_lock:
            items = [v for v in self.issues.values() if v["plugin"] and v["kind"] in ERR_PRIO]
        groups = {}
        for it in items:
            for pl in it["plugin"].split(", "):
                if pl:
                    g = groups.setdefault(pl, [0, it])
                    g[0] += it["count"]
                    if it["epoch"] > g[1]["epoch"]:
                        g[1] = it
        lines = [self.t("err_line", who=pl, n=g[0], what=f"{self.t('k_' + g[1]['kind'])}: {short(g[1]['summary'], 90)}")
                 for pl, g in sorted(groups.items(), key=lambda x: -x[1][0])]
        self._dialog(self.t("err_list"), "\n\n".join(lines) or self.t("err_none"))

    def _s_problems(self, li):
        t = self.t
        return self._spaced([
            Header(text=t("h_search")),
            Switch(key="err_watch", text=t("err_watch"), default=True, icon="msg_info", subtext=t("err_watch_sub")),
            Selector(key="err_interval", text=t("err_interval"), default=1, icon="msg_list", items=ERR_INTERVAL_ITEMS[li]),
            Switch(key="scan_logs", text=t("scan_logs"), default=True, icon="msg_log", subtext=t("scan_logs_sub")),
            Switch(key="scan_exits", text=t("scan_exits"), default=True, icon="msg_info"),
            Switch(key="env_check", text=t("env_check"), default=True, icon="msg_info"),
            Switch(key="track_changes", text=t("track_changes"), default=True, icon="msg_info"),
            Selector(key="issue_ttl", text=t("issue_ttl"), default=1, icon="msg_list", items=TTL_ITEMS[li]),
            Switch(key="hide_bg_lowmem", text=t("hide_lowmem"), default=True, icon="msg_info", subtext=t("hide_lowmem_sub")),
            Text(text=t("clr_issues"), subtext=t("clr_issues_sub"), icon="msg_delete", red=True, on_click=lambda v: self._act_clear_issues()),
            Header(text=t("h_tell")),
            Switch(key="notify_issues", text=t("notify_issues"), default=True, icon="msg_info"),
            Switch(key="err_popup", text=t("err_popup"), default=True, icon="msg_info", subtext=t("err_popup_sub")),
            Selector(key="err_level", text=t("err_level"), default=0, icon="msg_list", items=[t("lv_all"), t("lv_serious")]),
            Input(key="err_ignore", text=t("err_ignore"), default="", subtext=t("err_ignore_sub"), icon="msg_list"),
            Header(text=t("h_check")),
            Text(text=t("err_test"), subtext=t("err_test_sub"), icon="msg_retry", on_click=lambda v: self._act_err_test()),
        ])

    def _health_scan(self, manual):
        if not self.health_lock.acquire(False):
            return
        try:
            self._rlang = None
            ids = self._plugin_ids()
            if manual or self.get_setting("scan_logs", True):
                self._parse_log(self._read_logcat(), ids)
            if (manual or not self.exit_done) and self.get_setting("scan_exits", True):
                self._exit_issues(ids)
                self.exit_done = True
            self._plugin_state_issues()
            if self.get_setting("env_check", True):
                self._env_issues()
            self._notify_new_issues()
        except Exception as e:
            self.ev(f"health scan: {e}\n{traceback.format_exc()}")
        finally:
            self.health_lock.release()
        if manual:
            run_on_ui_thread(self._act_issues)

    # ---------- нагрузка на CPU по потокам ----------

    @staticmethod
    def _read_stat(path):
        with open(path, "r") as f:
            data = f.read()
        rp = data.rfind(")")
        comm = data[data.find("(") + 1:rp]
        fields = data[rp + 2:].split()
        return comm, int(fields[11]) + int(fields[12])

    def _cpu_read(self):
        total = self._read_stat("/proc/self/stat")[1]
        threads = {}
        for tid in os.listdir("/proc/self/task"):
            try:
                comm, ticks = self._read_stat(f"/proc/self/task/{tid}/stat")
                threads[int(tid)] = (comm, ticks)
            except Exception:
                continue
        return {"t": time.time(), "total": total, "threads": threads}

    def _cpu_sample(self, now):
        cur = self._cpu_read()
        prev, self.cpu_prev = self.cpu_prev, cur
        self._res_sample(now, cur)
        if not prev:
            return
        dt = cur["t"] - prev["t"]
        if dt <= 0:
            return
        hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        total_pct = (cur["total"] - prev["total"]) / hz / dt * 100
        py = {t.native_id: t for t in threading.enumerate() if getattr(t, "native_id", None)}
        frames = sys._current_frames()
        ids = None
        rows = []
        for tid, (comm, ticks) in cur["threads"].items():
            old = prev["threads"].get(tid)
            pct = (ticks - old[1]) / hz / dt * 100 if old else 0.0
            if pct < 0.3:
                continue
            own = False
            plugins = []
            th = py.get(tid)
            if th is not None:
                own = th.name.startswith("StallDoctor")
                fr = frames.get(th.ident)
                if fr is not None and not own:
                    if ids is None:
                        ids = self._plugin_ids()
                    text = " ".join(f.filename for f in traceback.extract_stack(fr))
                    plugins = self._plugins_from_paths(text, ids)
                comm = th.name
            rows.append((comm, round(pct, 1), plugins, own))
        rows.sort(key=lambda r: -r[1])
        self.cpu_hist.append({"t": now, "total": round(total_pct, 1), "paused": self.paused, "top": rows[:8]})
        limit = 5.0 if self.paused else 30.0
        self.cpu_hot = self.cpu_hot + 1 if total_pct >= limit else 0
        if self.cpu_hot >= 3:
            self.cpu_hot = 0
            plug = []
            for r in rows[:5]:
                if r[1] < 2.0:
                    continue
                for pl in r[2]:
                    if pl not in plug:
                        plug.append(pl)
            if not plug or not self.get_setting("cpu_warn", True):
                return
            top = ", ".join(f"{r[0]} {r[1]}%" for r in rows[:4])
            mode = self.t("mode_bg" if self.paused else "mode_fg")
            self._add_issue("cpu", plug, self.t("i_cpu", p=int(total_pct), mode=mode, x=top), [f"{r[0]}: {r[1]}%" for r in rows[:8]], now)

    def _cpu_lines(self, limit=8):
        hist = list(self.cpu_hist)
        if not hist:
            return [self.t("cpu_none")]
        agg = {}
        for h in hist:
            for comm, pct, plugins, own in h["top"]:
                key = (comm, tuple(plugins), own)
                agg[key] = agg.get(key, 0.0) + pct
        lines = []
        for (comm, plugins, own), tot in sorted(agg.items(), key=lambda kv: -kv[1])[:limit]:
            who = self.t("cpu_own") if own else (self.t("cpu_who", x=", ".join(plugins)) if plugins else "")
            lines.append(self.t("cpu_line", name=comm, pct=round(tot / len(hist), 1), who=who))
        avg = sum(h["total"] for h in hist) / len(hist)
        return [f"Σ {avg:.1f}%"] + lines

    # ---------- общие помощники для сохранённого состояния ----------

    def _jget(self, key, default):
        try:
            v = json.loads(self.get_setting(key, "") or "")
            return default if v is None else v
        except Exception:
            return default

    def _jset(self, key, val):
        try:
            self.set_setting(key, json.dumps(val, ensure_ascii=False))
        except Exception as _e:
            _swallow(_e)

    def _note_culprits(self, names):
        names = [n for n in names if n and n != "stall_doctor"]
        if not names:
            return
        d = self._jget("culprits", {})
        if not isinstance(d, dict):
            d = {}
        for n in names:
            d[n] = int(d.get(n, 0)) + 1
        if len(d) > 40:
            d = dict(sorted(d.items(), key=lambda kv: -kv[1])[:40])
        self._jset("culprits", d)

    # ---------- самопроверка совместимости ----------

    def _selfcheck(self):
        res = []

        def add(name, ok, detail=""):
            res.append((name, bool(ok), str(detail)))

        for cn in ("org.telegram.messenger.MessagesController", "org.telegram.tgnet.ConnectionsManager",
                   "org.telegram.messenger.SharedConfig", "org.telegram.messenger.MessagesStorage",
                   "com.exteragram.messenger.plugins.PluginsController", "com.exteragram.messenger.ExteraConfig"):
            try:
                add(cn.rsplit(".", 1)[1], find_class(cn))
            except Exception as e:
                add(cn.rsplit(".", 1)[1], False, e)
        try:
            fm = self._field_map("mc", "org.telegram.messenger.MessagesController", MC_FIELDS_RE)
            add("MessagesController fields", fm, ", ".join(sorted(fm)))
            add("MessagesController.gettingDifference",
                any("gettingdifference" in k.lower() and "channel" not in k.lower() for k in fm))
            pv = self._progress_vals(self._mc_fields(self._acc()))
            add("progress fields readable (pts/seq)", pv is not None,
                ", ".join(k for k, _ in pv) if pv else "the Updating/getDifference freeze rule falls back to time-based")
            fc = self._field_map("cm", "org.telegram.tgnet.ConnectionsManager", CM_FIELDS_RE)
            add("ConnectionsManager.appPaused", any(k.lower() == "apppaused" for k in fc), ", ".join(sorted(fc)))
        except Exception as e:
            add("fields", False, e)
        try:
            cm = get_connections_manager(self._acc())
            for name in ("getConnectionState", "isNetworkOnline", "resumeNetworkMaybe", "checkConnection"):
                add(f"ConnectionsManager.{name}", hasattr(cm, name))
        except Exception as e:
            add("ConnectionsManager instance", False, e)
        try:
            pc = jclass("com.exteragram.messenger.plugins.PluginsController").getInstance()
            for name in ("getPlugins", "getWatchdog", "shutdown", "init", "setPluginEnabled"):
                add(f"PluginsController.{name}", hasattr(pc, name))
            cfg = jclass("com.exteragram.messenger.ExteraConfig")
            add("ExteraConfig.setPluginsEngine", hasattr(cfg, "setPluginsEngine"))
        except Exception as e:
            add("PluginsController instance", False, e)
        for k, (ok, d) in list(self.hook_status.items()):
            add("hook " + k, ok, d)
        try:
            import subprocess
            r = subprocess.run(["logcat", "-d", "-t", "1"], capture_output=True, text=True, timeout=10)
            add("logcat", r.returncode == 0, (r.stderr or "")[:80])
        except Exception as e:
            add("logcat", False, e)
        try:
            ctx = jclass("org.telegram.messenger.ApplicationLoader").applicationContext
            add("ActivityManager.getHistoricalProcessExitReasons",
                hasattr(ctx.getSystemService("activity"), "getHistoricalProcessExitReasons"))
        except Exception as e:
            add("exit reasons", False, e)
        try:
            for n, ok, d in self._logcheck():
                add("logpipe: " + n, ok, d)
        except Exception as e:
            add("logpipe", False, e)
        self.selfcheck = res
        try:
            self._app_version_check(res)
        except Exception as e:
            self.ev(f"app version check: {e}")
        self._log("SELFCHECK ok=%d total=%d failed=%s" % (sum(1 for _, ok, _ in res if ok), len(res),
                                                          ",".join(n.replace(" ", "_") for n, ok, _ in res if not ok) or "-"))
        self._log("HOOKS " + " ".join(f"{k.replace(' ', '_')}={v[0]}" for k, v in sorted(self.hook_status.items())))
        bad = [n for n, ok, _ in res if not ok]
        if bad:
            self._rlang = None
            self.ev(self.t("e_selfcheck", x=", ".join(bad)))
        return res

    def _logcheck(self):
        """Сквозная проверка конвейера журнала: пишем тестовые строки, читаем их через logcat и прогоняем через
        настоящий разбор (приёмник sink не трогает ни список проблем, ни курсор журнала)."""
        res = []

        def add(name, ok, detail=""):
            res.append((name, bool(ok), str(detail)))

        mark = "sdchk%d" % int(time.time() * 1000)
        tb_tag = "sdchk_tb"
        try:
            Log = jclass("android.util.Log")
            Log.e("plugin.sdchk", "marker " + mark)
            Log.w(tb_tag, "Traceback (most recent call last):")
            Log.w(tb_tag, '  File "/data/user/0/x/files/plugins/sdchk_probe.py", line 7, in run')
            Log.w(tb_tag, "ValueError: " + mark)
            add("write to log", True)
        except Exception as e:
            add("write to log", False, e)
            return res
        self.stop.wait(1.5)
        lines = [ln for ln in self._read_logcat(1500) if "sdchk" in ln]
        mine = next((ln for ln in lines if mark in ln), "")
        add("logcat returns our line", bool(mine), f"{len(lines)} lines")
        add("line format (threadtime) recognised", bool(mine and LOG_RE.match(mine)), short(mine, 110))
        got = []

        def sink(kind, plugins, summary, detail, epoch, pkgs=(), unique=False, extra=None):
            got.append((kind, list(plugins or []), str(summary)))

        try:
            self._parse_log(lines, {"sdchk_probe", "sdchk"}, sink)
        except Exception as e:
            add("parser runs", False, e)
            return res
        add("error line with tag plugin.* becomes an issue",
            any(k == "plugin_log" and p == ["sdchk"] for k, p, _ in got), len(got))
        add("Python Traceback parsed, plugin named from file path",
            any(k == "pytrace" and p == ["sdchk_probe"] and mark in sm for k, p, sm in got),
            "; ".join(f"{k}:{','.join(p)}" for k, p, _ in got)[:100])
        return res

    def _act_logcheck(self):
        self._rlang = None
        BulletinHelper.show_info(self.t("logchk_busy"))

        def work():
            res = self._logcheck()
            self._rlang = None
            text = "\n".join(("OK    " if ok else "FAIL  ") + n + (f": {short(d, 120)}" if d else "") for n, ok, d in res)
            title = self.t("logchk_title")
            run_on_ui_thread(lambda: self._dialog(title, text))

        threading.Thread(target=self._safe, args=(work,), name="StallDoctorLogCheck", daemon=True).start()

    # ---------- смена версии приложения ----------

    @staticmethod
    def _app_ver():
        try:
            bv = jclass("org.telegram.messenger.BuildVars")
            return f"{bv.BUILD_VERSION_STRING} ({bv.BUILD_VERSION})"
        except Exception as e:
            _swallow(e)
            return None

    def _app_version_check(self, res):
        """Запоминает версию приложения и то, что в ней находилось. После обновления пишет, что перестало находиться."""
        cur = self._app_ver()
        if not cur:
            return
        ok_names = sorted(n for n, ok, _ in res if ok and not n.startswith(("hook ", "logpipe")))
        prev = self._jget("app_ver", None)
        if isinstance(prev, dict) and prev.get("app") and prev["app"] != cur:
            failed = {n for n, ok, _ in res if not ok}
            lost = [n for n in prev.get("ok", []) if n in failed]
            self._jset("app_change", {"t": time.time(), "a": prev["app"], "b": cur, "lost": lost[:15]})
            self._rlang = None
            self.ev(self.t("e_app_changed", a=prev["app"], b=cur))
        self._jset("app_ver", {"app": cur, "ok": ok_names, "sd": __version__})

    def _app_change_lines(self):
        ch = self._jget("app_change", None)
        if not isinstance(ch, dict) or time.time() - float(ch.get("t", 0)) > 14 * 86400:
            return []
        t = self.t
        out = [t("app_chg_line", t=time.strftime("%m-%d %H:%M", time.localtime(float(ch.get("t", 0)))), a=ch.get("a"), b=ch.get("b"))]
        out.append(t("app_chg_lost", x=", ".join(ch["lost"])) if ch.get("lost") else t("app_chg_ok"))
        return out + [""]

    def _bg_selfcheck(self):
        if self.stop.wait(20):
            return
        try:
            self._selfcheck()
        except Exception as e:
            self.ev(f"selfcheck: {e}")

    def _selfcheck_lines(self):
        head = self._app_change_lines()
        if not self.selfcheck:
            return head + [self.t("selfcheck_wait")]
        return head + [("OK    " if ok else "FAIL  ") + n + (f": {short(d, 120)}" if d else "") for n, ok, d in self.selfcheck]

    def _act_selfcheck(self):
        self._rlang = None
        if self.selfcheck is None:
            BulletinHelper.show_info(self.t("selfcheck_wait"))
            return
        self._dialog(self.t("selfcheck"), "\n".join(self._selfcheck_lines()))

    # ---------- реестр хуков по плагинам (лучшая попытка, структура не документирована) ----------

    @staticmethod
    def _jiter(v, limit=400):
        res = []
        try:
            if hasattr(v, "entrySet"):
                it = v.entrySet().iterator()
                while it.hasNext() and len(res) < limit:
                    e = it.next()
                    res.append((e.getKey(), e.getValue()))
                return "map", res
            if hasattr(v, "iterator"):
                it = v.iterator()
                while it.hasNext() and len(res) < limit:
                    res.append((None, it.next()))
                return "coll", res
        except Exception as _e:
            _swallow(_e)
        return None, res

    @staticmethod
    def _jf(obj, *names):
        for n in names:
            for attempt in (n, "get" + n[:1].upper() + n[1:]):
                try:
                    v = getattr(obj, attempt)
                    if callable(v) and not isinstance(v, (bool, int, float, str)):
                        v = v()
                    if v is not None:
                        return v
                except Exception as _e:
                    _swallow(_e)
            try:
                f = obj.getClass().getDeclaredField(n)
                f.setAccessible(True)
                v = f.get(obj)
                if v is not None:
                    return v
            except Exception as _e:
                _swallow(_e)
        return None

    def _hook_owner(self, obj):
        v = self._jf(obj, "pluginId", "plugin_id", "pluginID")
        if isinstance(v, str) and v:
            return v
        p = self._jf(obj, "plugin")
        if p is not None:
            v = self._jf(p, "id")
            if isinstance(v, str) and v:
                return v
        return None

    def _hook_name(self, obj):
        v = self._jf(obj, "name", "requestName", "hookName", "methodName", "method")
        if v is not None:
            return short(v, 60)
        try:
            return str(obj.getClass().getSimpleName())
        except Exception:
            return short(obj, 40)

    def _hooks_overview(self, force=False):
        if not force and time.time() - self.hooks_cache[0] < 60:
            return self.hooks_cache[1]
        out = {}
        try:
            pc = jclass("com.exteragram.messenger.plugins.PluginsController").getInstance()
            fields = pc.getClass().getDeclaredFields()
            for i in range(len(fields)):
                f = fields[i]
                if not re.search(r"hook", str(f.getName()), re.I):
                    continue
                try:
                    f.setAccessible(True)
                    kind, items = self._jiter(f.get(pc))
                except Exception:
                    continue
                for key, val in items:
                    if kind == "map" and isinstance(key, str) and hasattr(val, "iterator") and not hasattr(val, "entrySet"):
                        for _, h in self._jiter(val, 200)[1]:
                            out.setdefault(key, []).append(self._hook_name(h))
                    else:
                        pid = self._hook_owner(val) or (key if kind == "map" and isinstance(key, str) else None)
                        if pid:
                            out.setdefault(pid, []).append(self._hook_name(val))
        except Exception as e:
            self.ev(f"hooks overview: {e}")
        self.hooks_cache = (time.time(), out)
        return out

    def _hook_suspects(self):
        res = {}
        for pid, names in self._hooks_overview().items():
            hit = [n for n in names if UPD_RE.search(n)]
            if hit:
                res[pid] = hit
        return res

    def _hooks_lines(self):
        ov = self._hooks_overview()
        if not ov:
            return [self.t("hooks_none")]
        lines = [self.t("hooks_line", p=pid, n=len(names), x=" (" + ", ".join(sorted(set(names))[:6]) + ")")
                 for pid, names in sorted(ov.items())]
        owners = {}
        for pid, names in ov.items():
            for nm in set(names):
                owners.setdefault(nm, set()).add(pid)
        shared = [f"{nm}: {', '.join(sorted(p))}" for nm, p in sorted(owners.items()) if len(p) >= 2]
        if shared:
            lines.append(self.t("hooks_shared", x="; ".join(shared[:8])))
        return lines

    # ---------- дамп контроллера плагинов ----------

    def _dump_class(self, lines, title, target, obj=None, name_filter=None):
        lines.append("")
        lines.append("=" * 6 + " " + title + " " + "=" * 6)
        hookish = 0
        try:
            c = target.getClass()
            if str(c.getName()) == "java.lang.Class":
                c = target
            fields = c.getDeclaredFields()
            for i in range(len(fields)):
                f = fields[i]
                fname = str(f.getName())
                ftype = str(f.getType().getSimpleName())
                if name_filter and not name_filter.search(fname):
                    continue
                mark = ""
                if HOOKISH_RE.search(fname + " " + ftype):
                    mark = "  <== hook?"
                    hookish += 1
                val = ""
                if obj is not None or name_filter:
                    try:
                        f.setAccessible(True)
                        v = f.get(obj)
                        sz = ""
                        if v is not None and hasattr(v, "size"):
                            try:
                                sz = f" size={v.size()}"
                            except Exception as _e:
                                _swallow(_e)
                        val = " = " + short(v, 100) + sz
                    except Exception:
                        val = " = ?"
                lines.append(f"  field {ftype} {fname}{val}{mark}")
            if not name_filter:
                ms = c.getDeclaredMethods()
                names = []
                for i in range(len(ms)):
                    m = ms[i]
                    mn = str(m.getName())
                    if mn.startswith(("lambda$", "access$", "$r8$")):
                        continue
                    params = m.getParameterTypes()
                    sig = ", ".join(str(params[j].getSimpleName()) for j in range(len(params)))
                    mark = ""
                    if HOOKISH_RE.search(mn):
                        mark = "  <== hook?"
                        hookish += 1
                    names.append(f"  method {mn}({sig}){mark}")
                lines.extend(sorted(set(names)))
        except Exception as e:
            lines.append(f"  (error: {e})")
        return hookish

    def dump_controller(self):
        self._rlang = None
        lines = [f"Stall Doctor {__version__} · controller dump · {time.strftime('%Y-%m-%d %H:%M:%S')}"]
        hookish = 0
        pc = None
        try:
            pc = jclass("com.exteragram.messenger.plugins.PluginsController").getInstance()
        except Exception as e:
            lines.append(f"PluginsController: {e}")
        if pc is not None:
            hookish += self._dump_class(lines, "PluginsController (instance)", pc, obj=pc)
            try:
                w = pc.getWatchdog()
                if w is not None:
                    hookish += self._dump_class(lines, "PluginsWatchdog (instance)", w, obj=w)
            except Exception as e:
                lines.append(f"watchdog: {e}")
            try:
                it = pc.getPlugins().values().iterator()
                if it.hasNext():
                    first = it.next()
                    hookish += self._dump_class(lines, "Plugin (first instance)", first, obj=first)
            except Exception as e:
                lines.append(f"plugin: {e}")
        try:
            eng = find_class("com.exteragram.messenger.plugins.PythonPluginsEngine")
            if eng:
                hookish += self._dump_class(lines, "PythonPluginsEngine (class)", eng)
        except Exception as e:
            lines.append(f"engine: {e}")
        try:
            cfg = find_class("com.exteragram.messenger.ExteraConfig")
            if cfg:
                self._dump_class(lines, "ExteraConfig (plugin/engine/menu fields)", cfg,
                                 name_filter=re.compile(r"plugin|engine|menu", re.I))
        except Exception as e:
            lines.append(f"config: {e}")
        lines.append("")
        lines.append("=" * 6 + " hooks overview " + "=" * 6)
        lines.extend(self._hooks_lines())
        path = os.path.join(self.base_dir, f"dump_{time.strftime('%Y%m%d_%H%M%S')}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines)[:200000] + "\n")
        for old in self._dumps()[:-3]:
            try:
                os.remove(old)
            except Exception as _e:
                _swallow(_e)
        msg = self.t("dump_done", f=os.path.basename(path), n=hookish)
        self.ev(msg)
        run_on_ui_thread(lambda: self._dialog(self.t("dump"), msg))
        return path

    def _dumps(self):
        try:
            return [os.path.join(self.base_dir, n) for n in sorted(os.listdir(self.base_dir))
                    if n.startswith("dump_") and n.endswith(".txt")]
        except Exception:
            return []

    def _act_dump(self):
        self._rlang = None
        BulletinHelper.show_info(self.t("dumping"))
        threading.Thread(target=self._safe, args=(self.dump_controller,), name="StallDoctorDump", daemon=True).start()

    def _act_send_dump(self):
        self._rlang = None
        d = self._dumps()
        if not d:
            return BulletinHelper.show_info(self.t("no_dump"))
        self._send_path(d[-1])

    def _safe(self, fn):
        try:
            fn()
        except Exception as e:
            self.ev(f"{getattr(fn, '__name__', 'task')}: {e}\n{traceback.format_exc()}")

    def _send_path(self, p, quiet=False):
        try:
            acc = self._acc()
            uid = get_user_config(acc).getClientUserId()
            try:
                send_document(uid, p, account=acc)
            except TypeError:
                send_document(uid, p)
            if not quiet:
                BulletinHelper.show_success(self.t("sent"))
        except Exception as e:
            self.ev(f"send {os.path.basename(str(p))}: {e}")
            if not quiet:
                BulletinHelper.show_error(self.t("send_fail", e=e))

    # ---------- восстановление: перезагрузка плагинов и перезапуск, с запоминанием результата ----------

    def _restart_app(self):
        def go():
            from org.telegram.messenger import ApplicationLoader
            from android.app import PendingIntent, AlarmManager
            from android.os import Process
            from java.lang import System
            ctx = ApplicationLoader.applicationContext
            intent = ctx.getPackageManager().getLaunchIntentForPackage(ctx.getPackageName())
            intent.addFlags(0x10000000 | 0x00008000)
            pi = PendingIntent.getActivity(ctx, 7791, intent, 0x04000000 | 0x10000000)
            ctx.getSystemService("alarm").set(AlarmManager.RTC, System.currentTimeMillis() + 500, pi)
            Process.killProcess(Process.myPid())
            System.exit(0)
        run_on_ui_thread(go, 600)

    def _before_recovery(self, action):
        self._rlang = None
        try:
            cname = self.state_names.get(int(get_connections_manager(self._acc()).getConnectionState()), "?")
        except Exception:
            cname = "?"
        self._jset("recovery_pending", {"action": action, "t": time.time(), "state": cname})
        self.ev(self.t("e_rec_start", a=self.t("act_" + action)))
        self._flush_journal()

    def recover_restart(self):
        self._before_recovery("restart")
        self._restart_app()

    def recover_reload(self):
        """Схема из Plugin Restarter 3.0.0: выключить движок, shutdown, включить, init. На устройстве не подтверждена."""
        self._rlang = None
        try:
            from java import dynamic_proxy
            Runnable = jclass("java.lang.Runnable")
            cfg = jclass("com.exteragram.messenger.ExteraConfig")
            ctl = jclass("com.exteragram.messenger.plugins.PluginsController").getInstance()
            if not (hasattr(cfg, "setPluginsEngine") and hasattr(ctl, "shutdown") and hasattr(ctl, "init")):
                raise RuntimeError("methods missing")
        except Exception as e:
            self.ev(f"reload prepare: {e}")
            run_on_ui_thread(lambda: BulletinHelper.show_error(self.t("rec_no_engine")))
            return
        restart = self._restart_app
        base = dynamic_proxy(Runnable)
        done = threading.Event()

        class AfterInit(base):
            def __init__(s):
                super().__init__()

            def run(s):
                done.set()

        class AfterStop(base):
            def __init__(s):
                super().__init__()

            def run(s):
                try:
                    cfg.setPluginsEngine(True)
                    ctl.init(AfterInit())
                except Exception:
                    done.set()
                    restart()

        def watchdog():
            if not done.is_set():
                try:
                    cfg.setPluginsEngine(True)
                except Exception as _e:
                    _swallow(_e)
                restart()

        self._before_recovery("reload")
        timer = threading.Timer(25, watchdog)
        timer.daemon = True
        timer.start()
        cfg.setPluginsEngine(False)
        ctl.shutdown(AfterStop())

    def _recovery_eval(self):
        pend = self._jget("recovery_pending", None)
        if not isinstance(pend, dict):
            return
        self._jset("recovery_pending", None)
        if time.time() - float(pend.get("t", 0)) > 900:
            return
        for _ in range(20):
            if self.stop.wait(5):
                return
        now = time.time()
        bad = [n for n, p in self.probes.items() if n != "ping" and p.pending_for(now) >= PROBE_LIMIT]
        try:
            cname = self.state_names.get(int(get_connections_manager(self._acc()).getConnectionState()), "?")
        except Exception:
            cname = "?"
        helped = (not bad) and cname == "Connected" and not self.last_gd
        log = self._jget("recovery_log", [])
        if not isinstance(log, list):
            log = []
        log.append({"t": now, "a": pend.get("action"), "ok": bool(helped), "s": pend.get("state")})
        self._jset("recovery_log", log[-30:])
        self._rlang = None
        action = self.t("act_" + str(pend.get("action")))
        res = self.t("rec_yes" if helped else "rec_no")
        self.ev(self.t("e_rec_done", a=action, r=res, s=pend.get("state")))
        self._episode_mark_recovery(f"{action}: {res}")
        run_on_ui_thread(lambda: BulletinHelper.show_info(self.t("rec_toast", a=action, r=res)))

    def _recovery_stats(self):
        log = self._jget("recovery_log", [])
        agg = {}
        for e in log if isinstance(log, list) else []:
            a = e.get("a")
            n, h = agg.get(a, (0, 0))
            agg[a] = (n + 1, h + (1 if e.get("ok") else 0))
        return agg

    def _recovery_verdict(self):
        """Правило из справочника: помогает перезагрузка плагинов, виновата живая логика плагина; помогает только
        полный перезапуск, застрявшее состояние в клиенте. Нужно минимум по 2 попытки каждого способа."""
        agg = self._recovery_stats()
        r, s2 = agg.get("reload"), agg.get("restart")
        if not r or not s2 or r[0] < 2 or s2[0] < 2:
            return None
        rr, sr = r[1] / r[0], s2[1] / s2[0]
        if rr >= 0.6:
            return self.t("v_rec_reload", h=r[1], n=r[0])
        if rr <= 0.3 and sr >= 0.6:
            return self.t("v_rec_restart", h=r[1], n=r[0], h2=s2[1], n2=s2[0])
        return None

    def _recovery_summary(self):
        agg = self._recovery_stats()
        if not agg:
            return ""
        return "; ".join(f"{self.t('act_' + str(a))}: {h}/{n}" for a, (n, h) in sorted(agg.items()))

    def _act_recover(self, action):
        self._rlang = None
        if not self._adv_ok():
            return
        key = "rec_confirm_" + action
        fn = self.recover_reload if action == "reload" else self.recover_restart
        self._confirm(self.t("rec_title"), self.t(key),
                      lambda: threading.Thread(target=self._safe, args=(fn,), name="StallDoctorRecover", daemon=True).start())

    def _act_recovery_stats(self):
        self._rlang = None
        s = self._recovery_summary()
        self._dialog(self.t("rec_stats"), s or self.t("rec_none"))

    def _confirm(self, title, text, on_ok):
        try:
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return
            b = AlertDialogBuilder(act)
            b.set_title(title)
            b.set_message(text)
            b.set_positive_button(self.t("go"), lambda bld, w: (bld.dismiss(), on_ok()))
            b.set_negative_button(self.t("cancel"), lambda bld, w: bld.dismiss())
            b.show()
        except Exception as e:
            self.ev(f"confirm: {e}")

    # ---------- проверка: смоделировать потерю сети ----------

    def sim_toggle(self):
        if self.sim_active:
            self.sim_cancel.set()
            return
        self.sim_cancel = threading.Event()
        threading.Thread(target=self._safe, args=(self._sim_run,), name="StallDoctorSim", daemon=True).start()

    def _sim_say(self, key, **kw):
        msg = self.t(key, **kw)
        run_on_ui_thread(lambda: BulletinHelper.show_info(msg))
        self.ev("sim: " + msg)

    def _sim_wait(self, want_online, timeout):
        end = time.time() + timeout
        while time.time() < end and not self.sim_cancel.is_set() and not self.stop.is_set():
            net = self._os_online(self._acc())
            if net is not None and bool(net) == want_online:
                return True
            self.sim_cancel.wait(2)
        return False

    def _sim_run(self):
        self.sim_active = True
        self._rlang = None
        try:
            self._sim_say("sim_off")
            if not self._sim_wait(False, 180):
                return self._sim_say("sim_abort")
            t0 = time.time()
            self._sim_say("sim_down")
            if not self._sim_wait(True, 2400):
                return self._sim_say("sim_abort")
            dur = time.time() - t0
            self.last_offline = (time.time(), dur)
            self.net_down_since = None
            self._sim_say("sim_up", d=fmt_dur(dur))
            if self.sim_cancel.wait(90):
                return self._sim_say("sim_abort")
            self.make_report(self.t("sim_reason", d=fmt_dur(dur)), True)
        finally:
            self.sim_active = False

    # ---------- профиль задержек очередей ----------

    def _lat_collect(self):
        for n, p in self.probes.items():
            if p.last_latency is None or not p.done_at or p.done_at <= self.lat_seen.get(n, 0):
                continue
            self.lat_seen[n] = p.done_at
            d = self.lat.setdefault(n, collections.OrderedDict())
            e = d.setdefault(int(p.done_at // 900), [0, 0.0, 0.0])
            e[0] += 1
            e[1] += p.last_latency
            e[2] = max(e[2], p.last_latency)
            while len(d) > 24:
                d.popitem(last=False)

    def _lat_lines(self):
        out = []
        for n, d in self.lat.items():
            if not d:
                continue
            cells = [f"{time.strftime('%H:%M', time.localtime(b * 900))} {s / c * 1000:.0f}/{m * 1000:.0f}"
                     for b, (c, s, m) in list(d.items())[-8:] if c]
            out.append(f"{n} (ms avg/max): " + " | ".join(cells))
        return out or [self.t("lat_none")]

    def _lat_slow(self):
        res = []
        for n in ("ui", "plugins", "stage", "global"):
            d = self.lat.get(n)
            if not d or len(d) < 4:
                continue
            avgs = [s / c for c, s, m in d.values() if c]
            if len(avgs) < 4:
                continue
            base = sorted(avgs[:-2])[len(avgs[:-2]) // 2]
            cur = avgs[-1]
            if cur > 0.3 and cur > 5 * max(base, 0.01):
                res.append(f"{n}: {base * 1000:.0f} → {cur * 1000:.0f} ms")
        return res

    # ---------- отчёт по одному плагину ----------

    def _plugin_report(self, pid):
        t = self.t
        out = [t("pr_head", v=__version__, p=pid, ts=time.strftime("%Y-%m-%d %H:%M:%S"))]
        try:
            out.append(t("r_app", b=str(jclass("org.telegram.messenger.BuildVars").BUILD_VERSION_STRING), a=self._acc()))
        except Exception as _e:
            _swallow(_e)
        found = False
        info = next((p for p in self._plugins_info() if str(p.get("id")) == pid), None)
        if info:
            flag = ""
            if info["not_responding"]:
                flag += f" [{t('pl_noresp')}]"
            if info["error"]:
                flag += f" [{t('pl_err')}: {short(info['error'], 100)}]"
            out.append(t("pr_state", v=info["version"], e=info["enabled"], f=flag))
        cnt = int((self._jget("culprits", {}) or {}).get(pid, 0))
        if cnt:
            out.append(t("pr_culprit", n=cnt))
            found = True
        with self.issue_lock:
            mine = [it for it in self.issues.values() if pid in it["plugin"].split(", ")]
        if mine:
            found = True
            out.append(t("pr_issues"))
            for it in sorted(mine, key=lambda v: -v["epoch"])[:10]:
                out.append(t("i_line", who=pid, what=f"{t('k_' + it['kind'])}: {short(it['summary'], 110)}", n=it["count"],
                             t=time.strftime("%m-%d %H:%M", time.localtime(it["epoch"]))))
                out.extend("    " + d for d in it["detail"][:8])
        names = self._hooks_overview().get(pid)
        if names:
            found = True
            out.append(t("pr_hooks", n=len(names), x=" (" + ", ".join(sorted(set(names))[:8]) + ")"))
        p = self._latest(False)
        if p:
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
                keep = set()
                for i, ln in enumerate(lines):
                    if pid in ln:
                        keep.update(range(max(0, i - 1), min(len(lines), i + 2)))
                if keep:
                    found = True
                    out.append(t("pr_report"))
                    out.extend(lines[i] for i in sorted(keep)[:70])
            except Exception as e:
                self.ev(f"plugin report: {e}")
        if not found:
            out.append(t("pr_none"))
        return "\n".join(out) + "\n"

    def _plugin_pick_items(self, *a):
        try:
            self._rlang = None
            t = self.t
            cul = self._jget("culprits", {}) or {}
            with self.issue_lock:
                with_issues = {pl for it in self.issues.values() for pl in it["plugin"].split(", ") if pl}
            ids = sorted(set(self._plugin_ids()) | set(cul) | with_issues)
            ids.sort(key=lambda x: (-int(cul.get(x, 0)), x not in with_issues, x))
            items = [Header(text=t("pr_pick"))]
            for pid in ids[:80]:
                sub = []
                if cul.get(pid):
                    sub.append(t("pl_culprit_n", n=cul[pid]))
                if pid in with_issues:
                    sub.append(t("pl_has_issues"))
                kw = {"text": pid, "icon": "msg_info", "on_click": (lambda v, pid=pid: self._act_plugin_report(pid))}
                if sub:
                    kw["subtext"] = " · ".join(sub)
                items.append(Text(**kw))
            return items
        except Exception as e:
            self.ev(f"plugin pick: {e}")
            return [Text(text=self.t("empty"))]

    def _act_plugin_report(self, pid):
        try:
            self._rlang = None
            text = self._plugin_report(pid)
            copy_to_clipboard(text)
            self._dialog(self.t("pr_head", v=__version__, p=pid, ts="")[:60], text)
        except Exception as e:
            self.ev(f"plugin report act: {e}")

    # ---------- перенос настроек ----------

    def _act_cfg_export(self):
        try:
            self._rlang = None
            data = self.export_settings()
            if isinstance(data, str):
                data = json.loads(data)
            try:
                d = dict(data)
            except Exception:
                d = {}
                it = data.entrySet().iterator()
                while it.hasNext():
                    e = it.next()
                    d[str(e.getKey())] = e.getValue()
            d = {k: v for k, v in d.items() if k not in INTERNAL_KEYS}
            copy_to_clipboard(json.dumps(d, ensure_ascii=False, default=str))
        except Exception as e:
            self.ev(f"cfg export: {e}")
            BulletinHelper.show_error(self.t("send_fail", e=e))

    def _act_cfg_import(self):
        try:
            self._rlang = None
            ctx = jclass("org.telegram.messenger.ApplicationLoader").applicationContext
            clip = ctx.getSystemService("clipboard").getPrimaryClip()
            txt = str(clip.getItemAt(0).getText())
            d = json.loads(txt)
            if not isinstance(d, dict) or not d:
                raise ValueError("not settings")
            d = {k: v for k, v in d.items() if k not in INTERNAL_KEYS}
            self.import_settings(d, reload_settings=True)
            BulletinHelper.show_success(self.t("cfg_done"))
        except Exception as e:
            self.ev(f"cfg import: {e}")
            BulletinHelper.show_error(self.t("cfg_bad"))

    # ---------- расширенные действия ----------

    def _adv_ok(self):
        if self.get_setting("advanced", False):
            return True
        self._rlang = None
        BulletinHelper.show_info(self.t("adv_need"))
        return False

    # ---------- изменения плагинов ----------

    def _plugin_snapshot_check(self):
        infos = self._plugins_info()
        if not infos:
            return
        cur = {str(p["id"]): [str(p["version"]), bool(p["enabled"])] for p in infos if p.get("id")}
        by_id = {str(p["id"]): p for p in infos if p.get("id")}
        prev = self._jget("plugin_snapshot", None)
        self._jset("plugin_snapshot", cur)
        if not isinstance(prev, dict):
            return
        now = time.time()
        changes = []
        bisecting = isinstance(self._jget("bisect", None), dict)
        for pid, (v, en) in cur.items():
            if pid == "stall_doctor":
                continue
            o = prev.get(pid)
            if o is None:
                changes.append({"t": now, "id": pid, "k": "new"})
            elif o[0] != v:
                changes.append({"t": now, "id": pid, "k": "updated", "a": o[0], "b": v})
            elif o[1] != en and not bisecting:
                ch = {"t": now, "id": pid, "k": "enabled" if en else "disabled"}
                info = by_id.get(pid) or {}
                own = now - self.own_toggle.get(pid, 0) < 900       # выключали мы сами (кнопка, деление пополам)
                if not en and not own and (info.get("error") or info.get("not_responding")):
                    ch["k"] = "sysdisabled"
                    ch["e"] = short(str(info.get("error") or "not responding"), 120)
                changes.append(ch)
        for pid in prev:
            if pid not in cur and pid != "stall_doctor":
                changes.append({"t": now, "id": pid, "k": "removed"})
        if not changes:
            return
        old = self._jget("plugin_changes", [])
        if not isinstance(old, list):
            old = []
        self._jset("plugin_changes", (old + changes)[-40:])
        self._rlang = None
        for c in changes:
            self.ev(f"{c['id']}: {self._chg_text(c)}")

    def _chg_text(self, c):
        if c.get("k") == "updated":
            return self.t("chg_updated", a=c.get("a"), b=c.get("b"))
        if c.get("k") == "sysdisabled":
            return self.t("chg_sysdisabled", e=c.get("e", ""))
        return self.t("chg_" + str(c.get("k")))

    def _changes_lines(self, window, limit=15):
        now = time.time()
        ch = self._jget("plugin_changes", [])
        ch = [c for c in ch if isinstance(c, dict) and now - c.get("t", 0) <= window] if isinstance(ch, list) else []
        return [f"{c['id']}: {self._chg_text(c)} ({self.t('ago', d=fmt_dur(now - c['t']))})" for c in reversed(ch[-limit:])]

    def _act_changes(self):
        self._rlang = None
        self._dialog(self.t("chg_title"), "\n".join(self._changes_lines(14 * 86400, 30)) or self.t("chg_none"))

    # ---------- переходы соединения: события вместо опроса ----------

    def _install_observer(self):
        self.obs = None
        if not self.get_setting("observer", True):
            return
        try:
            from client_utils import NotificationCenterDelegate
            nc_cls = jclass("org.telegram.messenger.NotificationCenter")
            self.obs_id = int(nc_cls.didUpdateConnectionState)
            doctor = self

            class ConnObserver(NotificationCenterDelegate):
                def didReceivedNotification(self_o, id, account, args):
                    try:
                        doctor._on_conn_event(int(account))
                    except Exception as _e:
                        _swallow(_e)

            self.obs = ConnObserver()
            self.obs_acc = self._acc()
            cu.get_notification_center(self.obs_acc).addObserver(self.obs, self.obs_id)
            self.hook_status["connection observer"] = (True, f"account {self.obs_acc}")
        except Exception as e:
            self.obs = None
            self.hook_status["connection observer"] = (False, str(e))

    def _remove_observer(self):
        try:
            if self.obs is not None:
                cu.get_notification_center(self.obs_acc).removeObserver(self.obs, self.obs_id)
                self.obs = None
        except Exception as e:
            self._log(f"remove observer: {e}")

    def _on_conn_event(self, account):
        if account != self.obs_acc:
            return
        conn = int(get_connections_manager(account).getConnectionState())
        if conn != self.last_conn:
            self._conn_changed(conn, self.last_net, True)

    def _conn_changed(self, conn, net, defer):
        now = time.time()
        a = self.state_names.get(self.last_conn, self.last_conn)
        b = self.state_names.get(conn, conn)
        if a == "Updating" and self.conn_since:
            self.ev(self.t("e_upd_took", d=fmt_dur(now - self.conn_since)), defer=defer)
        self.ev(self.t("e_conn", a=a, b=b, n=net), defer=defer)
        self.conn_hist.append((now, str(a), str(b), net))
        self.last_conn = conn
        self.conn_since = now

    def _conn_lines(self):
        return [f"{fmt_ts(t0)}  {a} → {b}  (net={n})" for t0, a, b, n in list(self.conn_hist)[-20:]] or [self.t("lat_none")]

    # ---------- прокси: смены без адресов ----------

    def _proxy_state(self):
        if not self._proxy_enabled():
            return ("off", None)
        try:
            p = jclass("org.telegram.messenger.SharedConfig").currentProxy
            addr = self._jf(p, "address")
            port = self._jf(p, "port")
            kind = "MTProto" if self._jf(p, "secret") else "SOCKS5"
            fp = hashlib.md5(f"{addr}:{port}".encode("utf-8")).hexdigest()[:8]
            return (fp, kind)
        except Exception:
            return ("on", "?")

    def _proxy_label(self, st):
        if st[0] == "off":
            return self.t("px_off")
        n = self.proxy_alias.setdefault(st[0], len(self.proxy_alias) + 1)
        return f"#{n} {st[1]}"

    def _proxy_track(self, now):
        st = self._proxy_state()
        if self.proxy_cur is None:
            self.proxy_cur = st
            return
        if st != self.proxy_cur:
            old, self.proxy_cur = self.proxy_cur, st
            self.last_proxy_change = now
            self.proxy_changes.append(now)
            self._rlang = None
            self.ev(self.t("e_proxy", a=self._proxy_label(old), b=self._proxy_label(st)))

    def _proxy_changes_hour(self, now):
        return sum(1 for x in list(self.proxy_changes) if now - x <= 3600)

    # ---------- история зависаний и закономерности ----------

    def _episodes(self):
        e = self._jget("episodes", [])
        return e if isinstance(e, list) else []

    def _episode_update(self, t0, **kw):
        eps = self._episodes()
        for e in reversed(eps):
            if e.get("t0") == t0:
                e.update(kw)
                self._jset("episodes", eps)
                return

    def _episode_start(self, now, reason, s):
        cname = self.state_names.get(s["conn"], str(s["conn"]))
        lo = self.last_offline
        off = lo[1] if lo and now - lo[0] < 1800 else 0
        if self.net_down_since:
            off = max(off, now - self.net_down_since)
        chg = any(isinstance(c, dict) and now - c.get("t", 0) < 6 * 3600 for c in (self._jget("plugin_changes", []) or []))
        px = bool(self.last_proxy_change and now - self.last_proxy_change < 180)
        self.ep_cur = {"t0": now, "r": short(reason, 100), "s": cname, "off": int(off), "chg": bool(chg), "px": px,
                       "cul": [], "v": "", "rec": ""}
        eps = self._episodes()
        eps.append(dict(self.ep_cur, open=True))
        self._jset("episodes", eps[-40:])

    def _episode_note(self, verdict, culprits):
        if self.ep_cur:
            self.ep_cur["v"] = short(verdict[0] if verdict else "", 120)
            self.ep_cur["cul"] = sorted(set(culprits))
            self._episode_update(self.ep_cur["t0"], v=self.ep_cur["v"], cul=self.ep_cur["cul"])

    def _episode_end(self, now):
        if self.ep_cur:
            self._episode_update(self.ep_cur["t0"], dur=int(now - self.ep_cur["t0"]), open=False)
            self.ep_prev = self.ep_cur
            self.ep_prev_end = now
            self.ep_cur = None

    def _episode_mark_recovery(self, text):
        eps = self._episodes()
        if eps and time.time() - float(eps[-1].get("t0", 0)) < 7200:
            eps[-1]["rec"] = text
            self._jset("episodes", eps)

    def _episode_pattern(self):
        eps = self._episodes()
        n = len(eps)
        if n < 3:
            return None
        thr = self._pick("offline", OFFLINE_VALUES, 1)
        for test, key in ((lambda e: e.get("off", 0) >= thr, "v_pat_off"), (lambda e: e.get("chg"), "v_pat_chg"),
                          (lambda e: e.get("px"), "v_pat_px")):
            k = sum(1 for e in eps if test(e))
            if k >= 3 and k / n >= 0.6:
                return self.t(key, k=k, n=n)
        return None

    def _episode_lines(self, limit=10):
        out = []
        for e in reversed(self._episodes()[-limit:]):
            dur = fmt_dur(e["dur"]) if e.get("dur") is not None else "…"
            line = f"{time.strftime('%m-%d %H:%M', time.localtime(e.get('t0', 0)))} · {dur} · {e.get('s')} · {e.get('r')}"
            if e.get("cul"):
                line += " · " + ", ".join(e["cul"])
            if e.get("rec"):
                line += " · " + str(e["rec"])
            out.append(line)
        return out

    def _episode_stats(self):
        eps = self._episodes()
        n = len(eps)
        if not n:
            return [self.t("ep_none")]
        t = self.t
        out = [t("ep_total", n=n)]
        durs = [e["dur"] for e in eps if e.get("dur")]
        if durs:
            out.append(t("ep_avg", d=fmt_dur(sum(durs) / len(durs))))
        thr = self._pick("offline", OFFLINE_VALUES, 1)
        for label, test in (("ep_off", lambda e: e.get("off", 0) >= thr), ("ep_chg", lambda e: e.get("chg")),
                            ("ep_px", lambda e: e.get("px"))):
            k = sum(1 for e in eps if test(e))
            if k:
                out.append(t(label, k=k, n=n))
        cnt = collections.Counter(p for e in eps for p in (e.get("cul") or []))
        if cnt:
            out.append(t("ep_cul", x=", ".join(f"{p} ×{c}" for p, c in cnt.most_common(5))))
        rs = self._recovery_summary()
        if rs:
            out.append(t("ep_rec", x=rs))
        return out

    def _act_episodes(self):
        self._rlang = None
        text = "\n".join(self._episode_stats() + [""] + self._episode_lines())
        self._dialog(self.t("ep_title"), text)

    def _act_episodes_csv(self):
        try:
            import csv
            import io
            self._rlang = None
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["start", "duration_s", "state", "offline_before_s", "plugin_change", "proxy_change", "culprits", "recovery", "verdict"])
            for e in self._episodes():
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("t0", 0))), e.get("dur", ""), e.get("s", ""),
                            e.get("off", 0), int(bool(e.get("chg"))), int(bool(e.get("px"))), ";".join(e.get("cul") or []),
                            e.get("rec", ""), e.get("v", "")])
            copy_to_clipboard(buf.getvalue())
        except Exception as e:
            self.ev(f"episodes csv: {e}")

    # ---------- деление пополам ----------

    def _plugin_set_enabled(self, pid, flag):
        try:
            self.own_toggle[pid] = time.time()
        except Exception as e:
            _swallow(e)
        ctl = jclass("com.exteragram.messenger.plugins.PluginsController").getInstance()
        try:
            ctl.setPluginEnabled(pid, bool(flag), None)
            return True
        except Exception as e1:
            try:
                ctl.getPlugins().get(pid).setEnabled(bool(flag))
                return True
            except Exception as e2:
                self.ev(f"set enabled {pid}: {e1}; {e2}")
                return False

    def _bisect_subtext(self):
        st = self._jget("bisect", None)
        if isinstance(st, dict):
            return self.t("bis_state", r=st.get("round", 0), n=len(st.get("suspects", [])), d=len(st.get("disabled", [])))
        return self.t("bis_sub")

    def _act_bisect(self):
        self._rlang = None
        if not self._adv_ok():
            return
        st = self._jget("bisect", None)
        if isinstance(st, dict):
            self._bisect_dialog(st)
        else:
            self._confirm(self.t("bis"), self.t("bis_confirm"),
                          lambda: threading.Thread(target=self._safe, args=(self.bisect_start,), name="StallDoctorBisect", daemon=True).start())

    def bisect_start(self):
        self._rlang = None
        keep = {x.strip() for x in str(self.get_setting("bisect_keep", "stall_doctor")).split(",") if x.strip()} | {"stall_doctor"}
        cands = sorted(str(p["id"]) for p in self._plugins_info() if p.get("enabled") and p.get("id") and str(p["id"]) not in keep)
        if len(cands) < 2:
            run_on_ui_thread(lambda: BulletinHelper.show_info(self.t("bis_few")))
            return
        st = {"suspects": cands, "disabled": [], "round": 0, "half": []}
        self.ev(self.t("e_bis_start", n=len(cands)))
        self._bisect_next(st)

    def _bisect_apply(self, st, half):
        for pid in list(st["disabled"]):
            if pid not in half and self._plugin_set_enabled(pid, True):
                st["disabled"].remove(pid)
        for pid in half:
            if pid not in st["disabled"]:
                if not self._plugin_set_enabled(pid, False):
                    return False
                st["disabled"].append(pid)
        return True

    def _bisect_next(self, st):
        s = st["suspects"]
        if len(s) <= 1:
            return self._bisect_finish(st)
        half = s[:len(s) // 2]
        if not self._bisect_apply(st, half):
            self._jset("bisect", st)
            run_on_ui_thread(lambda: BulletinHelper.show_error(self.t("bis_failed")))
            return
        st["round"] += 1
        st["half"] = half
        self._jset("bisect", st)
        self.stop.wait(3)
        run_on_ui_thread(lambda: self._bisect_dialog(st))

    def _bisect_dialog(self, st):
        try:
            self._rlang = None
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return
            names = ", ".join(st.get("disabled", [])[:12]) + ("…" if len(st.get("disabled", [])) > 12 else "")
            b = AlertDialogBuilder(act)
            b.set_title(self.t("bis"))
            b.set_message(self.t("bis_ask", r=st.get("round", 0), n=len(st.get("suspects", [])), d=names or "-"))
            b.set_positive_button(self.t("bis_yes"), lambda bld, w: (bld.dismiss(), self._bisect_answer(True)))
            b.set_negative_button(self.t("bis_no"), lambda bld, w: (bld.dismiss(), self._bisect_answer(False)))
            b.set_neutral_button(self.t("bis_cancel"), lambda bld, w: (bld.dismiss(), self._bisect_cancel()))
            b.show()
        except Exception as e:
            self.ev(f"bisect dialog: {e}")

    def _bisect_answer(self, frozen):
        def work():
            st = self._jget("bisect", None)
            if not isinstance(st, dict):
                return
            half = st.get("half", [])
            if frozen:      # зависает и без этой половины: виновник среди остальных
                st["suspects"] = [p for p in st["suspects"] if p not in half]
            else:           # перестало: виновник в выключенной половине
                st["suspects"] = list(half)
            self.ev(self.t("e_bis_round", r=st["round"], n=len(st["suspects"])))
            self._bisect_next(st)
        threading.Thread(target=self._safe, args=(work,), name="StallDoctorBisect", daemon=True).start()

    def _bisect_finish(self, st):
        culprit = st["suspects"][0] if st["suspects"] else None
        for pid in list(st["disabled"]):
            if pid != culprit:
                self._plugin_set_enabled(pid, True)
        if culprit:
            self._plugin_set_enabled(culprit, False)
            self._note_culprits([culprit, culprit])
            self.ev(self.t("e_bis_done", p=culprit))
        self._jset("bisect", None)
        msg = self.t("bis_done", p=culprit or "?")
        run_on_ui_thread(lambda: self._dialog(self.t("bis"), msg))

    def _bisect_cancel(self):
        def work():
            st = self._jget("bisect", None)
            if isinstance(st, dict):
                for pid in list(st.get("disabled", [])):
                    self._plugin_set_enabled(pid, True)
            self._jset("bisect", None)
            self.ev(self.t("e_bis_cancel"))
        threading.Thread(target=self._safe, args=(work,), name="StallDoctorBisect", daemon=True).start()

    # ---------- окружение, ресурсы, утечки потоков ----------

    def _env_lines(self):
        t = self.t
        yn = lambda v: t("unknown") if v is None else (t("yes") if v else t("no"))
        out = []
        try:
            build = jclass("android.os.Build")
            ver = jclass("android.os.Build$VERSION")
            abis = ""
            try:
                arr = build.SUPPORTED_ABIS
                abis = ", ".join(str(arr[i]) for i in range(len(arr)))
            except Exception as _e:
                _swallow(_e)
            out.append(f"Android {ver.RELEASE} (API {ver.SDK_INT}) · {build.MANUFACTURER} {build.MODEL} · {abis}")
        except Exception as e:
            out.append(f"android: {e}")
        try:
            bv = jclass("org.telegram.messenger.BuildVars")
            out.append(f"App: {bv.BUILD_VERSION_STRING} ({bv.BUILD_VERSION})")
        except Exception as _e:
            _swallow(_e)
        sdk = None
        try:
            eng = find_class("com.exteragram.messenger.plugins.PythonPluginsEngine")
            sdk = getattr(eng, "SDK_VERSION", None)
        except Exception as _e:
            _swallow(_e)
        out.append(f"Plugin SDK: {sdk if sdk is not None else '?'} · Python {sys.version.split()[0]} · Stall Doctor {__version__}")
        try:
            ctx = jclass("org.telegram.messenger.ApplicationLoader").applicationContext
            try:
                ign = bool(ctx.getSystemService("power").isIgnoringBatteryOptimizations(str(ctx.getPackageName())))
            except Exception:
                ign = None
            out.append(t("env_battery", v=yn(ign)))
            try:
                ds = int(ctx.getSystemService("connectivity").getRestrictBackgroundStatus())
                out.append(t("env_datasaver", v={1: t("no"), 2: t("env_ds_white"), 3: t("yes")}.get(ds, "?")))
            except Exception as _e:
                _swallow(_e)
        except Exception as _e:
            _swallow(_e)
        try:
            st = os.statvfs(self.base_dir)
            out.append(t("env_free", m=(st.f_bavail * st.f_frsize) >> 20))
        except Exception as _e:
            _swallow(_e)
        try:
            cfg = jclass("com.exteragram.messenger.ExteraConfig")
            out.append(t("env_safe", v=yn(bool(cfg.getPluginsSafeMode()))))
            out.append(t("env_engine", v=yn(bool(cfg.getPluginsEngine()))))
        except Exception as _e:
            _swallow(_e)
        out.extend(self._notif_lines())
        pl = self._proc_line()
        if pl:
            out.append(pl)
        infos = self._plugins_info()
        if infos:
            out.append(t("env_plugins", n=sum(1 for p in infos if p.get("enabled")), m=len(infos)))
        return out

    def _env_issues(self):
        now = time.time()
        try:
            st = os.statvfs(self.base_dir)
            free = (st.f_bavail * st.f_frsize) >> 20
            if free < 300:
                self._add_issue("storage", [], self.t("i_storage", m=free), [], now)
        except Exception as _e:
            _swallow(_e)
        try:
            cfg = jclass("com.exteragram.messenger.ExteraConfig")
            if bool(cfg.getPluginsSafeMode()):
                self._add_issue("safemode", [], self.t("i_safemode"), [], now, unique=True)
        except Exception as _e:
            _swallow(_e)
        try:
            self._notif_issues(now)
        except Exception as _e:
            _swallow(_e)

    def _res_sample(self, now, cur):
        try:
            nthreads = len(cur["threads"])
            try:
                nfd = len(os.listdir("/proc/self/fd"))
            except Exception:
                nfd = 0
            used, mx = self.mem if self.mem else (0, 0)
            self.res_hist.append((now, nthreads, nfd, used, mx))
            h = list(self.res_hist)
            med = lambda xs: sorted(xs)[len(xs) // 2]
            if len(h) >= 10:
                t0, t1 = med([x[1] for x in h[:3]]), med([x[1] for x in h[-3:]])
                if t1 - t0 >= 40 and t1 >= 1.5 * max(t0, 1):
                    groups = collections.Counter(re.sub(r"[\d\-_#]+$", "", c) for c, _ in cur["threads"].values())
                    top = ", ".join(f"{k or '?'} ×{v}" for k, v in groups.most_common(5))
                    self._add_issue("threads", [], self.t("i_threads", a=t0, b=t1, x=top),
                                    [f"{k or '?'}: {v}" for k, v in groups.most_common(8)], now)
                f0, f1 = h[0][2], h[-1][2]
                if f1 >= 700 or (f1 - f0 >= 200 and f1 >= 1.5 * max(f0, 1)):
                    self._add_issue("fd", [], self.t("i_fd", n=f1, a=f0), [], now)
            if len(h) >= 20 and h[-1][4]:
                third = len(h) // 3
                a = sum(x[3] for x in h[:third]) / third
                b = sum(x[3] for x in h[-third:]) / third
                if a > 0 and b > 1.35 * a and b / h[-1][4] > 0.6:
                    self._add_issue("memtrend", [], self.t("i_memtrend", a=int(a) >> 20, b=int(b) >> 20,
                                                           m=int((h[-1][0] - h[0][0]) // 60)), [], now)
            self._py_threads_check(now)
            self.part_fails["res"] = 0
        except Exception as e:
            self._part_fail("res", e)

    def _py_threads_check(self, now):
        ids = self._plugin_ids()
        me = threading.get_ident()
        frames = sys._current_frames()
        cnt = {}
        det = {}
        where = lambda f: f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" if f else "?"
        for th in threading.enumerate():
            if th.ident == me or th.name.startswith("StallDoctor"):
                continue
            fr = frames.get(th.ident)
            if fr is None:
                continue
            st = traceback.extract_stack(fr)
            text = " ".join(f.filename for f in st)
            for pid in self._plugins_from_paths(text, ids):
                cnt[pid] = cnt.get(pid, 0) + 1
                try:
                    own = next((f for f in reversed(st) if pid in f.filename), None)
                    key = (re.sub(r"\d+", "#", th.name) or "?", where(own), where(st[-1] if st else None))
                    det.setdefault(pid, collections.Counter())[key] += 1
                except Exception as _e:
                    _swallow(_e)
        self.pyth_hist.append(cnt)
        h = list(self.pyth_hist)
        if len(h) < 4:
            return
        for pid in cnt:
            series = [x.get(pid, 0) for x in h[-4:]]
            if series[-1] >= 10 and series[-1] - series[0] >= 6 and all(b >= a for a, b in zip(series, series[1:])):
                lines = [self.t("d_pyth_series", x=" → ".join(str(x) for x in series))]
                for (nm, own, last), n in det.get(pid, collections.Counter()).most_common(6):
                    lines.append(self.t("d_pythread", n=n, name=nm, own=own, last=last))
                self._add_issue("pythreads", [pid], self.t("i_pythreads", a=series[0], b=series[-1]), lines, now)

    # ---------- защита собственных частей ----------

    def _part(self, name, fn, *a):
        if name in self.dead_parts:
            return None
        try:
            r = fn(*a)
            self.part_fails[name] = 0
            return r
        except Exception as e:
            self._part_fail(name, e)
            return None

    def _part_fail(self, name, e):
        n = self.part_fails.get(name, 0) + 1
        self.part_fails[name] = n
        if n <= 3:
            self.ev(f"{name}: {e}")
        if n >= 5 and name not in self.dead_parts:
            self.dead_parts.add(name)
            self._rlang = None
            self.ev(self.t("e_part_dead", n=name))

    # ---------- стоимость самого плагина ----------

    def _self_cost_lines(self):
        t = self.t
        out = []
        hist = list(self.cpu_hist)
        own = [sum(r[1] for r in h["top"] if r[3]) for h in hist]
        if own:
            out.append(t("sc_cpu", p=f"{sum(own) / len(own):.2f}", n=max(1, len(hist) * CPU_EVERY // 60)))
        out.append(t("sc_threads", n=sum(1 for th in threading.enumerate() if th.name.startswith("StallDoctor"))))
        size = files = 0
        try:
            for fn in os.listdir(self.base_dir):
                try:
                    size += os.path.getsize(os.path.join(self.base_dir, fn))
                    files += 1
                except Exception as _e:
                    _swallow(_e)
        except Exception as _e:
            _swallow(_e)
        out.append(t("sc_disk", k=size >> 10, n=files))
        keys = set(INTERNAL_KEYS) | {"plugin_snapshot", "plugin_changes", "episodes", "bisect"}
        state = sum(len(str(self.get_setting(k, "") or "")) for k in keys)
        out.append(t("sc_state", k=state >> 10))
        sw = sorted(_SWALLOWED.items(), key=lambda kv: -kv[1][0])
        if sw:
            out.append(t("sc_swallow", n=sum(v[0] for _, v in sw), k=len(sw)))
            for key, (cnt, last, ts) in sw[:6]:
                out.append(f"    {key} ×{cnt}: {last}")
        return out

    def _act_selfcost(self):
        self._rlang = None
        self._dialog(self.t("sc_btn"), "\n".join(self._self_cost_lines()))

    # ---------- микрозависания интерфейса ----------

    def _main_stack(self):
        th = jclass("android.os.Looper").getMainLooper().getThread()
        arr = th.getStackTrace()
        return [str(arr[i]) for i in range(len(arr))]

    def _jank_loop(self):
        while not self.stop.is_set():
            if self.paused or not self.get_setting("jank_watch", False):
                if self.stop.wait(2):
                    return
                continue
            try:
                self._jank_once()
                self.part_fails["jank"] = 0
            except Exception as e:
                self._part_fail("jank", e)
                if "jank" in self.dead_parts:
                    return
            if self.stop.wait(0.2):
                return

    def _jank_once(self):
        ev = threading.Event()
        posted = time.time()
        run_on_ui_thread(lambda: ev.set())
        stacks = []
        while not ev.wait(0.05):
            w = time.time() - posted
            if w >= JANK_MS / 1000 and len(stacks) < 4 and (not stacks or time.time() - stacks[-1][0] >= 0.1):
                stacks.append((time.time(), self._main_stack()))
            if w > 5 or self.stop.is_set():
                break
        self._jank_record(time.time() - posted, [s for _, s in stacks])

    def _jank_record(self, lat, stacks):
        J = self.jank
        idx = 0 if lat < 0.05 else 1 if lat < 0.1 else 2 if lat < 0.2 else 3 if lat < 0.5 else 4
        J["hist"][idx] += 1
        J["n"] += 1
        J["worst"] = max(J["worst"], lat)
        if lat < JANK_MS / 1000:
            return
        now = time.time()
        ids = self._plugin_ids()
        plug = set()
        top = None
        for fr in stacks:
            plug.update(self._match_plugins(self._foreign_pkgs(fr), ids))
            if top is None and fr:
                top = next((f for f in fr if not f.startswith(FRAMEWORK_PREFIXES)), fr[0])
        if top:
            J["tops"][short(top, 100)] += 1
        for p in plug:
            J["plug"][p] += 1
        J["recent"].append((now, lat, sorted(plug)))
        for p in plug:
            cnt = sum(1 for t0, l, pl in J["recent"] if p in pl and now - t0 < 600 and l >= 0.2)
            if cnt >= 20 and cnt % 20 == 0:
                self._add_issue("jank", [p], self.t("i_jank", n=cnt), [short(top or "", 120)], now)

    def _jank_lines(self):
        J = self.jank
        if not J["n"]:
            return [self.t("jk_none")]
        h = J["hist"]
        out = [self.t("jk_hist", a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], w=int(J["worst"] * 1000))]
        if J["tops"]:
            out.append(self.t("jk_tops", x="; ".join(f"{k} ×{v}" for k, v in J["tops"].most_common(5))))
        if J["plug"]:
            out.append(self.t("jk_plug", x=", ".join(f"{k} ×{v}" for k, v in J["plug"].most_common(5))))
        return out

    # ---------- время операций (хуки на запросы, по желанию) ----------

    def pre_request_hook(self, request_name, account, request):
        try:
            if self.op_on:
                now = time.time()
                q = self.op_pending.setdefault((account, request_name), collections.deque(maxlen=50))
                while q and now - q[0] > 120:
                    q.popleft()
                q.append(now)
        except Exception as _e:
            _swallow(_e)
        return HookResult()

    def post_request_hook(self, request_name, account, response, error):
        # самого запроса здесь нет: сопоставляем по аккаунту, имени и порядку
        try:
            if self.op_on:
                q = self.op_pending.get((account, request_name))
                if q:
                    now = time.time()
                    self.ops.setdefault(request_name, collections.deque(maxlen=200)).append((now, now - q.popleft(), bool(error)))
        except Exception as _e:
            _swallow(_e)
        return HookResult()

    def _ops_lines(self):
        out = []
        for name, d in sorted(self.ops.items()):
            lats = sorted(x[1] for x in d)
            if not lats:
                continue
            out.append(self.t("ops_line", n=name, c=len(lats), e=sum(1 for x in d if x[2]), a=int(sum(lats) / len(lats) * 1000),
                              m=int(lats[len(lats) // 2] * 1000), p=int(lats[min(len(lats) - 1, int(len(lats) * 0.95))] * 1000),
                              x=int(lats[-1] * 1000)))
        return out or [self.t("ops_none")]

    def _ops_slow(self):
        res = []
        for name, d in self.ops.items():
            lat = [x[1] for x in d]
            if len(lat) < 30:
                continue
            base = sorted(lat[:-10])[len(lat[:-10]) // 2]
            cur = sum(lat[-10:]) / 10
            if cur > 1.0 and cur > 4 * max(base, 0.05):
                res.append(f"{name}: {base * 1000:.0f} → {cur * 1000:.0f} ms")
        return res

    # ---------- уведомления и фоновая работа ----------

    def _notif_info(self):
        info = {}
        try:
            ctx = jclass("org.telegram.messenger.ApplicationLoader").applicationContext
        except Exception:
            return info
        try:
            nm = ctx.getSystemService("notification")
            try:
                info["enabled"] = bool(nm.areNotificationsEnabled())
            except Exception as _e:
                _swallow(_e)
            try:
                chans = nm.getNotificationChannels()
                info["blocked"] = [str(chans.get(i).getId()) for i in range(chans.size()) if int(chans.get(i).getImportance()) == 0]
            except Exception as _e:
                _swallow(_e)
            try:
                info["dnd"] = int(nm.getCurrentInterruptionFilter())
            except Exception as _e:
                _swallow(_e)
        except Exception as _e:
            _swallow(_e)
        try:
            info["bucket"] = int(ctx.getSystemService("usagestats").getAppStandbyBucket())
        except Exception as _e:
            _swallow(_e)
        try:
            info["bgrestr"] = bool(ctx.getSystemService("activity").isBackgroundRestricted())
        except Exception as _e:
            _swallow(_e)
        try:
            tok = getattr(jclass("org.telegram.messenger.SharedConfig"), "pushString", None)
            info["push"] = bool(tok and len(str(tok)) > 0)
        except Exception as _e:
            _swallow(_e)
        return info

    def _notif_lines(self):
        t = self.t
        yn = lambda v: t("yes") if v else t("no")
        i = self._notif_info()
        out = []
        if "enabled" in i:
            out.append(t("env_notif", v=yn(i["enabled"])))
        if i.get("blocked"):
            out.append(t("env_blocked", x=", ".join(i["blocked"][:8])))
        if i.get("dnd") in (1, 2, 3, 4):
            out.append(t("env_dnd", v=t("env_dnd_" + str(i["dnd"]))))
        if "bucket" in i:
            out.append(t("env_bucket", v=BUCKETS.get(i["bucket"], str(i["bucket"]))))
        if "bgrestr" in i:
            out.append(t("env_bgrestr", v=yn(i["bgrestr"])))
        if "push" in i:
            out.append(t("env_push", v=yn(i["push"])))
        return out

    def _notif_issues(self, now):
        i = self._notif_info()
        if i.get("enabled") is False:
            self._add_issue("notif", [], self.t("i_notif_off"), [], now, unique=True)
        if i.get("bgrestr"):
            self._add_issue("notif", [], self.t("i_bgrestr"), [], now, unique=True)
        if i.get("bucket", 0) >= 40:
            self._add_issue("notif", [], self.t("i_bucket", b=BUCKETS.get(i["bucket"], i["bucket"])), [], now, unique=True)
        if i.get("push") is False:
            self._add_issue("notif", [], self.t("i_nopush"), [], now, unique=True)

    def _proc_line(self):
        try:
            start = int(jclass("android.os.Process").getStartElapsedRealtime())
            up = (int(jclass("android.os.SystemClock").elapsedRealtime()) - start) / 1000.0
            return self.t("env_proc", u=fmt_dur(up), l=fmt_dur(max(up - (time.time() - self.loaded_at), 0)))
        except Exception:
            return None

    # ---------- рейтинг подозреваемых ----------

    def _rank_suspects(self, now, chain, hard, soft):
        t = self.t
        sc = {}

        def add(pid, pts, why):
            if not pid or pid == "stall_doctor":
                return
            e = sc.setdefault(pid, [0.0, []])
            e[0] += pts
            if why not in e[1]:
                e[1].append(why)

        for p in chain:
            add(p, 3, t("rk_stack"))
        for p in hard:
            add(p, 3, t("rk_pyfrozen"))
        for p in soft:
            add(p, 1, t("rk_pywait"))
        weights = {"crash": 2, "ui": 2, "exit": 2, "pytrace": 1, "plugin_log": 1, "plugin_state": 2, "pythreads": 2, "jank": 1, "hook": 1}
        with self.issue_lock:
            items = list(self.issues.values())
        for it in items:
            if now - it["epoch"] > 6 * 3600 or it["kind"] not in weights:
                continue
            for pl in it["plugin"].split(", "):
                add(pl, weights[it["kind"]], t("k_" + it["kind"]))
        for line in self._jget("plugin_changes", []) if isinstance(self._jget("plugin_changes", []), list) else []:
            if isinstance(line, dict) and now - line.get("t", 0) < 6 * 3600:
                add(line.get("id"), 1, t("rk_changed"))
        try:
            for pid in self._hook_suspects():
                add(pid, 1, t("rk_hooks"))
        except Exception as _e:
            _swallow(_e)
        cul = self._jget("culprits", {})
        if isinstance(cul, dict):
            for pid, n in cul.items():
                if pid in sc:
                    add(pid, 0.5 * min(int(n), 4), t("rk_history"))
        ranked = sorted(((p, v[0], v[1]) for p, v in sc.items() if v[0] >= 2), key=lambda x: -x[1])[:5]
        return [f"{p} ({s:g}: {', '.join(r)})" for p, s, r in ranked]

    # ---------- просмотр перед отправкой и пакет для баг-репорта ----------

    def _act_preview(self, path=None):
        try:
            self._rlang = None
            path = path or self._latest(False)
            if not path:
                return BulletinHelper.show_info(self.t("no_reports"))
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            marks = [ln.strip()[:160] for ln in text.splitlines() if MARK_RE.search(ln)]
            body = self.t("pv_head", name=os.path.basename(path), k=len(text) >> 10, n=text.count("\n"), m=len(marks))
            body += "\n\n" + ("\n".join(marks[:15]) or self.t("pv_nomarks")) + "\n\n" + self.t("pv_start") + "\n" + text[:1200]
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return
            b = AlertDialogBuilder(act)
            b.set_title(self.t("pv_title"))
            b.set_message(body[:3500])
            b.set_positive_button(self.t("pv_send"), lambda bld, w: (bld.dismiss(), threading.Thread(
                target=self._send_path, args=(path,), name="StallDoctorSend", daemon=True).start()))
            b.set_negative_button(self.t("pv_copy"), lambda bld, w: (copy_to_clipboard(text), bld.dismiss()))
            b.set_neutral_button(self.t("pv_close"), lambda bld, w: bld.dismiss())
            b.show()
        except Exception as e:
            self.ev(f"preview: {e}")

    def _bundles(self):
        try:
            return [os.path.join(self.base_dir, n) for n in sorted(os.listdir(self.base_dir))
                    if n.startswith("bundle_") and n.endswith(".txt")]
        except Exception:
            return []

    def _tail_file(self, path, n):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()[-n:]
        except Exception:
            return []

    def make_bundle(self):
        self._rlang = None
        t = self.t
        if not self._latest(True):
            self.make_report("bundle", True)
        self._rlang = None
        parts = []

        def add(title, lines):
            parts.append("=" * 8 + " " + title + " " + "=" * 8)
            parts.extend(lines)
            parts.append("")

        p = self._latest(True)
        add("REPORT", self._tail_file(p, 400) if p else [t("no_reports")])
        add(t("s_env"), self._env_lines())
        add(t("ep_title"), self._episode_stats() + self._episode_lines(20))
        add(t("s_changes"), self._changes_lines(14 * 86400, 30) or [t("chg_none")])
        add(t("s_selfcheck"), self._selfcheck_lines())
        add(t("s_issues"), self._issues_text(40, detail=True) or [t("no_issues")])
        add(t("s_hooks"), self._hooks_lines())
        add(t("s_self"), self._self_cost_lines())
        d = self._dumps()
        if d:
            add("DUMP " + os.path.basename(d[-1]), self._tail_file(d[-1], 400)[:400])
        add(t("journal"), self._tail_file(self._journal_path(), 200))
        path = os.path.join(self.base_dir, f"bundle_{time.strftime('%Y%m%d_%H%M%S')}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(parts)[:400000] + "\n")
        for old in self._bundles()[:-3]:
            try:
                os.remove(old)
            except Exception as _e:
                _swallow(_e)
        self.ev(f"bundle: {os.path.basename(path)}")
        run_on_ui_thread(lambda: self._act_preview(path))
        return path

    def _act_bundle(self):
        self._rlang = None
        BulletinHelper.show_info(self.t("bn_building"))
        threading.Thread(target=self._safe, args=(self.make_bundle,), name="StallDoctorBundle", daemon=True).start()

    # ---------- настройки: страницы ----------

    @staticmethod
    def _spaced(items):
        """Между группами (перед каждым заголовком, кроме первого) ставит разделитель: блоки не сливаются."""
        out = []
        for i, it in enumerate(items):
            is_header = type(it).__name__ == "Header" or (isinstance(it, tuple) and it and it[0] == "Header")
            is_div = type(it).__name__ == "Divider" or (isinstance(it, tuple) and it and it[0] == "Divider")
            if i and is_header and out and not (type(out[-1]).__name__ == "Divider" or (isinstance(out[-1], tuple) and out[-1][0] == "Divider")):
                out.append(Divider())
            out.append(it)
        return out

    def _s_monitor(self, li):
        t = self.t
        return self._spaced([
            Header(text=t("h_basic")),
            Selector(key="threshold", text=t("threshold"), default=1, icon="msg_list", items=THR_ITEMS[li]),
            Switch(key="notify", text=t("notify"), default=True, icon="msg_info"),
            Switch(key="auto_rescue", text=t("rescue"), default=True, icon="msg_retry", subtext=t("rescue_sub")),
            Switch(key="cpu_warn", text=t("cpu_warn"), default=True, icon="msg_info", subtext=t("cpu_warn_sub")),
            Header(text=t("h_deep")),
            Switch(key="ping", text=t("ping"), default=True, icon="msg_send", subtext=t("ping_sub")),
            Switch(key="trace_hooks", text=t("trace"), default=True, icon="msg_log", subtext=t("trace_sub")),
            Switch(key="observer", text=t("observer"), default=True, icon="msg_info", subtext=t("observer_sub")),
            Switch(key="lat_profile", text=t("lat_profile"), default=True, icon="msg_list", subtext=t("lat_sub")),
            Switch(key="jank_watch", text=t("jank_watch"), default=False, icon="msg_info", subtext=t("jank_sub")),
            Switch(key="op_timing", text=t("op_timing"), default=False, icon="msg_log", subtext=t("op_sub")),
            Divider(text=t("hint_deep")),
            Header(text=t("h_net")),
            Switch(key="net_track", text=t("net_track"), default=True, icon="msg_info", subtext=t("net_track_sub")),
            Selector(key="offline", text=t("offline"), default=1, icon="msg_list", items=OFFLINE_ITEMS[li]),
            Selector(key="storm", text=t("storm"), default=2, icon="msg_list", items=STORM_ITEMS[li]),
            Switch(key="report_accounts", text=t("rep_acc"), default=True, icon="msg_info", subtext=t("rep_acc_sub")),
            Switch(key="auto_nudge", text=t("auto_nudge"), default=False, icon="msg_retry", subtext=t("auto_nudge_sub")),
        ])

    def _s_recover(self, li):
        t = self.t
        return self._spaced([
            Header(text=t("h_fix")),
            Text(text=t("rec_reload"), subtext=t("rec_reload_sub"), icon="msg_retry", accent=True, on_click=lambda v: self._act_recover("reload")),
            Text(text=t("rec_restart"), subtext=t("rec_restart_sub"), icon="msg_retry", on_click=lambda v: self._act_recover("restart")),
            Text(text=t("rec_stats"), subtext=self._recovery_summary() or t("rec_none"), icon="msg_info", on_click=lambda v: self._act_recovery_stats()),
            Divider(text=t("hint_fix")),
            Header(text=t("h_find")),
            Text(text=t("bis_btn"), subtext=self._bisect_subtext(), icon="msg_retry", on_click=lambda v: self._act_bisect()),
            Input(key="bisect_keep", text=t("bis_keep"), default="stall_doctor", subtext=t("bis_keep_sub"), icon="msg_list"),
            Header(text=t("h_test")),
            Switch(key="advanced", text=t("adv"), default=False, icon="msg_info", subtext=t("adv_sub")),
            Text(text=t("sim"), subtext=t("sim_sub"), icon="msg_retry", on_click=lambda v: self.sim_toggle()),
            Text(text=t("nudge"), subtext=t("nudge_sub"), icon="msg_retry",
                 on_click=lambda v: threading.Thread(target=self.nudge_now, name="StallDoctorNudge", daemon=True).start()),
            Text(text=t("unblock"), icon="msg_retry",
                 on_click=lambda v: self._adv_ok() and threading.Thread(target=self.rescue_now, daemon=True).start()),
        ])

    def _s_reports(self, li):
        t = self.t
        return self._spaced([
            Header(text=t("h_reports")),
            Text(text=t("bn_btn"), subtext=t("bn_sub"), icon="msg_share", accent=True, on_click=lambda v: self._act_bundle()),
            Text(text=t("pr_btn"), subtext=t("pr_btn_sub"), icon="msg_info", create_sub_fragment=lambda *a: self._plugin_pick_items()),
            Switch(key="auto_send", text=t("auto_send"), default=False, icon="msg_share", subtext=t("auto_send_sub")),
            Selector(key="report_lang", text=t("report_lang"), default=0, icon="msg_list", items=LANG_ITEMS[li]),
            Header(text=t("h_hist2")),
            Text(text=t("ep_btn"), subtext=t("ep_btn_sub"), icon="msg_list", on_click=lambda v: self._act_episodes()),
            Text(text=t("ep_csv"), icon="msg_copy", on_click=lambda v: self._act_episodes_csv()),
            Text(text=t("chg_btn"), subtext=t("chg_btn_sub"), icon="msg_list", on_click=lambda v: self._act_changes()),
            Text(text=t("journal"), icon="msg_log", on_click=lambda v: self._act_journal()),
            Header(text=t("h_dev")),
            Text(text=t("selfcheck"),
                 subtext=(t("selfcheck_sub", ok=sum(1 for _, ok, _ in self.selfcheck if ok), n=len(self.selfcheck))
                          if self.selfcheck else t("selfcheck_wait")),
                 icon="msg_info", on_click=lambda v: self._act_selfcheck()),
            Text(text=t("logchk_btn"), subtext=t("logchk_btn_sub"), icon="msg_log", on_click=lambda v: self._act_logcheck()),
            Text(text=t("sc_btn"), subtext=t("sc_btn_sub"), icon="msg_info", on_click=lambda v: self._act_selfcost()),
            Text(text=t("dump"), subtext=t("dump_sub"), icon="msg_log", on_click=lambda v: self._act_dump()),
            Text(text=t("dump_send"), icon="msg_share", on_click=lambda v: self._act_send_dump()),
            Header(text=t("h_data")),
            Text(text=t("cfg_export"), icon="msg_copy", on_click=lambda v: self._act_cfg_export()),
            Text(text=t("cfg_import"), icon="msg_copy", on_click=lambda v: self._act_cfg_import()),
            Text(text=t("clear"), icon="msg_delete", red=True, on_click=lambda v: self._act_clear()),
            Divider(text=t("hint_hist")),
        ])

    def create_settings(self):
        self._rlang = None
        li = ui_lang()
        try:
            n = int(self.get_setting("stat_episodes", 0) or 0)
            m = int(self.get_setting("stat_rescued", 0) or 0)
        except Exception:
            n = m = 0
        t = self.t
        self._prune_issues()
        found = len(self.issues)
        head = [
            Header(text=t("h_state")),
            Switch(key="monitor", text=t("monitor"), default=True, icon="msg_info", subtext=t("monitor_sub")),
            Text(text=t("status"), subtext=self.status_text(), icon="msg_info",
                 on_click=lambda v: self.set_setting("ui_refresh", time.time(), reload_settings=True)),
            Header(text=t("h_wrong")),
            Text(text=t("issues"), subtext=t("issues_sub", n=found) if found else t("issues_sub0"), icon="msg_list",
                 accent=bool(found), on_click=lambda v: self._act_issues()),
            Text(text=t("collect"), subtext=t("collect_sub"), icon="msg_retry", on_click=lambda v: self._act_manual()),
            Text(text=t("last_report"), subtext=t("last_report_sub"), icon="msg_log", on_click=lambda v: self._act_show()),
        ]
        tail = [Divider(), Text(text=t("stats"), subtext=t("stats_sub", n=n, m=m), icon="msg_info"), Divider(text=t("about"))]
        look = [
            Header(text=t("h_look")),
            Selector(key="ui_lang", text=t("ui_lang"), default=0, icon="msg_language", items=LANG_ITEMS[li], on_change=self._lang_changed),
            Switch(key="flat_settings", text=t("flat"), default=False, icon="msg_info", subtext=t("flat_sub")),
        ]
        if self.get_setting("flat_settings", False):
            return self._spaced(head + self._s_monitor(li) + self._s_problems(li) + self._s_recover(li)
                                + self._s_reports(li) + look) + tail

        def page(text, sub, fn, icon):
            return Text(text=text, subtext=sub, icon=icon, create_sub_fragment=lambda *a: fn(li))

        return self._spaced(head + [
            Header(text=t("h_tools")),
            page(t("sec_monitor"), t("sec_monitor_sub"), self._s_monitor, "msg_list"),
            page(t("sec_problems"), t("sec_problems_sub"), self._s_problems, "msg_report"),
            page(t("sec_recover"), t("sec_recover_sub"), self._s_recover, "msg_retry"),
            page(t("sec_reports"), t("sec_reports_sub"), self._s_reports, "msg_log"),
        ] + look) + tail

    # ---------- интерфейс ----------

    def _dialog(self, title, text):
        try:
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return
            b = AlertDialogBuilder(act)
            b.set_title(title)
            b.set_message(text if len(text) <= 3500 else text[:3500] + "…")
            b.set_positive_button("OK", lambda bld, w: bld.dismiss())
            b.set_negative_button(self.t("copy"), lambda bld, w: (copy_to_clipboard(text), bld.dismiss()))
            b.show()
        except Exception as e:
            self.ev(f"dialog: {e}")

    def status_text(self):
        try:
            self._rlang = None
            now = time.time()
            if not self.get_setting("monitor", True):
                return self.t("st_off")
            bad = [n for n, p in self.probes.items()
                   if n != "ping" or self.get_setting("ping", True)
                   if p.pending_for(now) >= (PING_LIMIT if n == "ping" else PROBE_LIMIT)]
            cname = self.state_names.get(self.last_conn, "?")
            if bad:
                head = self.t("st_freeze", what=", ".join(bad))
            elif self.suspicious:
                head = self.t("st_suspect") + ": " + cname
            else:
                head = self.t("st_ok")
            lat = " · ".join(f"{n} {p.last_latency * 1000:.0f} ms" for n, p in self.probes.items() if p.last_latency is not None)
            extra = self.t("st_issues", n=len(self.issues)) if self.issues else ""
            eps = self._episodes()
            if eps and eps[-1].get("t0"):
                extra += self.t("st_last", d=fmt_dur(now - eps[-1]["t0"]))
            return f"{head} · {cname}" + (f" · {lat}" if lat else "") + extra
        except Exception:
            return self.t("st_nodata")

    def _act_manual(self):
        self._rlang = None
        BulletinHelper.show_info(self.t("collecting"))
        threading.Thread(target=self.make_report, args=("manual", True), name="StallDoctorReport", daemon=True).start()

    def _act_scan(self):
        self._rlang = None
        BulletinHelper.show_info(self.t("scanning"))
        threading.Thread(target=self._health_scan, args=(True,), name="StallDoctorScan", daemon=True).start()

    def _act_clear_issues(self):
        self._rlang = None
        self._forget_issues()
        BulletinHelper.show_success(self.t("cleared"))

    # ---------- проблемы: объяснение простыми словами и полный отчёт ----------

    def _sorted_issues(self):
        self._prune_issues()
        with self.issue_lock:
            return sorted(self.issues.values(), key=lambda v: (v["plugin"] == "", v["kind"] not in ("crash", "exit", "ui", "pytrace"),
                                                               -v["count"], -v["epoch"]))

    def _exc_hint(self, it):
        if it["kind"] not in ("crash", "pytrace", "plugin_log", "hook"):
            return ""
        for rx, key in EXC_HINTS:
            if rx.search(it["summary"]):
                return self.t("xh_pref") + " " + self.t(key)
        return ""

    def _explain(self, it):
        """(что это значит, что делать) для одной проблемы."""
        t = self.t
        kind = it["kind"]
        who = [x for x in it["plugin"].split(", ") if x and x != "stall_doctor"]
        if kind == "exit":
            name = it["summary"].split(":", 1)[0].strip()
            means = t("x_exit_" + name) if ("x_exit_" + name) in STR else t("x_exit")
            ex = it.get("extra") or {}
            if "bg" in ex and name == "LOW_MEMORY":
                means += " " + t("x_exit_bg" if ex["bg"] else "x_exit_fg")
            if name in ("LOW_MEMORY", "EXCESSIVE_RESOURCE_USAGE"):
                with self.issue_lock:
                    rel = [v for v in self.issues.values() if v["kind"] in ("pythreads", "threads", "memtrend", "fd", "memory", "cpu")]
                names = []
                for v in rel:
                    s = (v["plugin"] + ": " if v["plugin"] else "") + t("k_" + v["kind"])
                    if s not in names:
                        names.append(s)
                if names:
                    means += " " + t("x_related", x="; ".join(names[:3]))
            todo = [t("a_exit_" + name) if ("a_exit_" + name) in STR else t("a_exit")]
        else:
            means = t("x_" + kind) if ("x_" + kind) in STR else ""
            todo = [t("a_" + kind)] if ("a_" + kind) in STR else []
        hint = self._exc_hint(it)
        if hint:
            means += " " + hint
        if who:
            todo.append(t("a_who", who=", ".join(who[:3])))
        elif kind in ATTR_KINDS:
            todo.append(t("a_np"))
        return means.strip(), " ".join(todo)

    @staticmethod
    def _top_culprit(items):
        for it in items:
            for p in it["plugin"].split(", "):
                if p and p != "stall_doctor":
                    return p
        return None

    def _issues_dialog_text(self, items, limit=3000, max_items=6):
        t = self.t
        out = [t("ir_intro")]
        used = len(out[0])
        shown = 0
        for i, it in enumerate(items[:max_items], 1):
            means, todo = self._explain(it)
            block = "\n".join([
                f"{i}. [{it['plugin'] or t('who_unknown')}] {t('k_' + it['kind'])}",
                f"{t('ir_what')}: {short(it['summary'], 200).rstrip(': ')}",
                f"{t('ir_when_l')}: " + t("ir_when", t=time.strftime("%m-%d %H:%M", time.localtime(it["epoch"])), n=it["count"]),
                f"{t('ir_means')}: {means}",
                f"{t('ir_todo')}: {todo}",
            ])
            if shown and used + len(block) > limit:
                break
            out.append(block)
            used += len(block)
            shown += 1
        if len(items) > shown:
            out.append(t("ir_rest", n=len(items) - shown))
        return "\n\n".join(out)

    def _issues_report(self):
        """Полный текст для автора плагина: объяснения, стеки, окружение, список плагинов, журнал событий."""
        self._rlang = self._report_lang_idx()
        try:
            t = self.t
            items = self._sorted_issues()
            try:
                infos = {str(p.get("id")): p for p in self._plugins_info()}
            except Exception:
                infos = {}
            out = [t("ir_title", v=__version__, ts=time.strftime("%Y-%m-%d %H:%M:%S"))]
            try:
                out.append(t("r_app", b=str(jclass("org.telegram.messenger.BuildVars").BUILD_VERSION_STRING), a=self._acc()))
            except Exception as _e:
                _swallow(_e)
            out += ["", t("ir_howto"), "", "== " + t("s_env") + " =="] + self._env_lines()
            out += ["", "== " + t("ir_head_n", n=len(items)) + " =="]
            if not items:
                out.append(t("no_issues"))
            for i, it in enumerate(items, 1):
                means, todo = self._explain(it)
                out += ["", f"#{i} [{it['plugin'] or t('who_unknown')}] {t('k_' + it['kind'])}",
                        f"{t('ir_what')}: {it['summary'].rstrip(': ')}",
                        f"{t('ir_when_l')}: " + t("ir_when", t=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it["epoch"])), n=it["count"]),
                        f"{t('ir_means')}: {means}",
                        f"{t('ir_todo')}: {todo}"]
                for pid in [x for x in it["plugin"].split(", ") if x]:
                    p = infos.get(pid)
                    if p:
                        flag = ""
                        if p.get("not_responding"):
                            flag += f" [{t('pl_noresp')}]"
                        if p.get("error"):
                            flag += f" [{t('pl_err')}: {short(p['error'], 100)}]"
                        out.append(t("ir_plugin", p=pid, v=p.get("version"), e=p.get("enabled"), f=flag))
                if it["detail"]:
                    out.append(t("ir_details"))
                    out.extend("    " + d for d in it["detail"][:14])
            out += ["", "== " + t("s_plugins") + " =="]
            for p in infos.values():
                flag = ""
                if p.get("not_responding"):
                    flag += f" [{t('pl_noresp')}]"
                if p.get("error"):
                    flag += f" [{t('pl_err')}: {short(p['error'], 100)}]"
                out.append(f"{p.get('id')} v{p.get('version')} enabled={p.get('enabled')}{flag}")
            out += ["", "== " + t("ir_events") + " =="] + list(self.events)[-40:]
            return "\n".join(out) + "\n"
        finally:
            self._rlang = None

    def _act_copy_issues(self):
        self._rlang = None
        BulletinHelper.show_info(self.t("ir_building"))

        def work():
            text = self._issues_report()

            def done():
                self._rlang = None
                copy_to_clipboard(text)
                BulletinHelper.show_success(self.t("ir_copied"))
            run_on_ui_thread(done)
        threading.Thread(target=self._safe, args=(work,), name="StallDoctorIssuesCopy", daemon=True).start()

    def _act_issues(self):
        try:
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return
            self._rlang = None
            t = self.t
            items = self._sorted_issues()
            b = AlertDialogBuilder(act)
            if not items:
                b.set_title(t("dlg_issues"))
                b.set_message(t("no_issues") + "\n\n" + t("ir_none_hint"))
                b.set_positive_button(t("ir_scan"), lambda bld, w: (bld.dismiss(), self._act_scan()))
                b.set_negative_button(t("ir_close"), lambda bld, w: bld.dismiss())
            else:
                culprit = self._top_culprit(items)
                b.set_title(t("dlg_issues_n", n=len(items)))
                b.set_message(self._issues_dialog_text(items)[:3500])
                b.set_positive_button(t("ir_copy"), lambda bld, w: (bld.dismiss(), self._act_copy_issues()))
                b.set_negative_button(t("ir_close"), lambda bld, w: bld.dismiss())
                b.set_neutral_button(t("ir_more"), lambda bld, w: (bld.dismiss(), self._issues_more(culprit)))
            b.show()
        except Exception as e:
            self.ev(f"issues dialog: {e}\n{traceback.format_exc()}")

    def _issues_more(self, culprit=None):
        try:
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return
            self._rlang = None
            t = self.t
            b = AlertDialogBuilder(act)
            b.set_title(t("ir_more_title"))
            b.set_message(t("ir_more_msg"))
            rescan = lambda bld, w: (bld.dismiss(), self._act_scan())
            clear = lambda bld, w: (bld.dismiss(), self._act_clear_issues())
            if culprit:
                label = t("ep_disable", who=short(culprit, 24))
                b.set_positive_button(label, lambda bld, w: (bld.dismiss(), self._confirm(
                    label, t("ir_disable_q", who=culprit), lambda: self._err_disable(culprit))))
                b.set_negative_button(t("ir_clear"), clear)
                b.set_neutral_button(t("ir_rescan"), rescan)
            else:
                b.set_positive_button(t("ir_rescan"), rescan)
                b.set_negative_button(t("ir_clear"), clear)
            b.show()
        except Exception as e:
            self.ev(f"issues more: {e}")

    def _report_dialog(self, title, body):
        """Окно отчёта: копировать полный текст, отправить в Избранное (с просмотром) или закрыть."""
        try:
            frag = get_last_fragment()
            act = frag.getParentActivity() if frag else None
            if not act:
                return
            self._rlang = None
            t = self.t
            b = AlertDialogBuilder(act)
            b.set_title(title)
            b.set_message((t("full_hint") + "\n\n" + body)[:3500])
            b.set_positive_button(t("ir_copy"), lambda bld, w: (bld.dismiss(), self._act_copy(False)))
            b.set_negative_button(t("ir_close"), lambda bld, w: bld.dismiss())
            b.set_neutral_button(t("rp_send"), lambda bld, w: (bld.dismiss(), self._act_preview()))
            b.show()
        except Exception as e:
            self.ev(f"report dialog: {e}")

    def _read(self, short_only):
        self._rlang = None
        p = self._latest(short_only)
        if not p:
            BulletinHelper.show_info(self.t("no_reports"))
            return None, None
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return p, f.read()

    def _act_show(self):
        try:
            p, text = self._read(True)
            if text:
                self._report_dialog(self.t("dlg_last") + " (" + os.path.basename(p)[7:-10] + ")", text)
        except Exception as e:
            self.ev(f"show report: {e}")

    def _act_copy(self, short_only):
        try:
            p, text = self._read(short_only)
            if text:
                copy_to_clipboard(text)
                BulletinHelper.show_success(self.t("copied"))
        except Exception as e:
            self.ev(f"copy report: {e}")

    def _act_send(self):
        try:
            self._rlang = None
            p = self._latest(False)
            if not p:
                return BulletinHelper.show_info(self.t("no_reports"))
            acc = self._acc()
            uid = get_user_config(acc).getClientUserId()
            try:
                send_document(uid, p, account=acc)
            except TypeError:
                send_document(uid, p)
            BulletinHelper.show_success(self.t("sent"))
        except Exception as e:
            self.ev(f"send report: {e}")
            BulletinHelper.show_error(self.t("send_fail", e=e))

    def _act_journal(self):
        self._rlang = None
        self._dialog(self.t("dlg_journal"), "\n".join(list(self.events)[-40:]) or self.t("empty"))

    def _act_clear(self):
        try:
            self._rlang = None
            for p in self._reports() + self._reports(True) + self._dumps() + self._bundles():
                os.remove(p)
            self.events.clear()
            self._forget_issues()
            try:
                os.remove(self._journal_path())
            except FileNotFoundError:
                pass
            self.journal_lines = 0
            BulletinHelper.show_success(self.t("cleared"))
        except Exception as e:
            self.ev(f"clear: {e}")
