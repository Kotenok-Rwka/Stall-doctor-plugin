#!/usr/bin/env python3
"""Проверка плагина на подключённом телефоне через DevServer exteraGram.

Что делает: пробрасывает порт (adb forward tcp:42690), загружает plugins/stall_doctor.py командой write_plugin,
перезагружает плагин и читает logcat по тегу plugin.stall_doctor. Успех: в логе есть маркер READY с нужной версией,
нет Traceback, самопроверка не нашла отсутствующих классов, а хуки установлены.

ВНИМАНИЕ: формат кадров DevServer в документации не описан (известны только поля "@" и "#"), поэтому скрипт пробует
два варианта: JSON с переводом строки и JSON с 4-байтовой длиной. Какой сработал, будет напечатано.
Скрипт на устройстве не проверялся: ни разу не запускался против настоящего DevServer.

Запуск: python3 -I tools/device_test.py [--wait 45] [--skip-upload] [--logcat-file лог.txt]"""
import argparse, json, os, re, socket, struct, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_PATH = os.path.join(ROOT, "plugins", "stall_doctor.py")
PORT = 42690
PLUGIN_ID = "stall_doctor"


def local_version(path=PLUGIN_PATH):
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', open(path, encoding="utf-8").read(), re.M)
    return m.group(1) if m else None


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def call(sock, msg, framing, timeout=10):
    data = json.dumps(msg, ensure_ascii=False).encode("utf-8")
    sock.settimeout(timeout)
    if framing == "line":
        sock.sendall(data + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return json.loads(buf.split(b"\n")[0].decode("utf-8"))
    sock.sendall(struct.pack(">I", len(data)) + data)
    n = struct.unpack(">I", _recvn(sock, 4))[0]
    return json.loads(_recvn(sock, n).decode("utf-8"))


def connect(host, port):
    """Возвращает (сокет, режим кадров), на котором DevServer ответил на ping."""
    last = None
    for framing in ("line", "len"):
        try:
            s = socket.create_connection((host, port), timeout=5)
            reply = call(s, {"@": "ping", "#": "1"}, framing, timeout=4)
            return s, framing, reply
        except Exception as e:
            last = e
            try:
                s.close()
            except Exception:
                pass
    raise ConnectionError(f"DevServer не ответил ни в одном режиме кадров: {last}")


def parse_log(text, expect_version):
    res = {"ready": None, "selfcheck": None, "hooks": None, "traceback": False, "errors": []}
    for line in text.splitlines():
        if "[SD] READY version=" in line:
            res["ready"] = line.split("version=", 1)[1].split()[0]
        m = re.search(r"\[SD\] SELFCHECK ok=(\d+) total=(\d+) failed=(\S+)", line)
        if m:
            res["selfcheck"] = (int(m.group(1)), int(m.group(2)), m.group(3))
        m = re.search(r"\[SD\] HOOKS (.*)$", line)
        if m:
            res["hooks"] = dict(kv.split("=", 1) for kv in m.group(1).split() if "=" in kv)
        if "Traceback (most recent call last)" in line:
            res["traceback"] = True
        if re.search(r"\s[EF]\s", line) and "plugin.stall_doctor" in line:
            res["errors"].append(line.strip()[:200])
    problems = []
    if res["ready"] is None:
        problems.append("нет маркера READY: плагин не загрузился или логи не читаются")
    elif expect_version and res["ready"] != expect_version:
        problems.append(f"версия на устройстве {res['ready']}, ожидалась {expect_version}")
    if res["traceback"]:
        problems.append("в логе есть Traceback")
    if res["errors"]:
        problems.append(f"ошибок в логе плагина: {len(res['errors'])}")
    if res["selfcheck"] is None:
        problems.append("самопроверка не отчиталась (она стартует через 20 с, увеличьте --wait)")
    if res["hooks"]:
        bad = [k for k, v in res["hooks"].items() if v != "True"]
        if bad:
            problems.append("не встали хуки: " + ", ".join(bad))
    res["problems"] = problems
    return res


def adb(*args, check=True):
    return subprocess.run(["adb", *args], capture_output=True, text=True, check=check)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wait", type=int, default=45)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--skip-upload", action="store_true")
    ap.add_argument("--logcat-file", help="не ходить в adb, разобрать готовый лог")
    args = ap.parse_args()
    version = local_version()
    if args.logcat_file:
        text = open(args.logcat_file, encoding="utf-8", errors="replace").read()
    else:
        adb("forward", f"tcp:{args.port}", f"tcp:{args.port}")
        adb("logcat", "-c", check=False)
        if not args.skip_upload:
            sock, framing, _ = connect("127.0.0.1", args.port)
            print("DevServer отвечает, режим кадров:", framing)
            content = open(PLUGIN_PATH, encoding="utf-8").read()
            print("write_plugin:", call(sock, {"@": "write_plugin", "#": "2", "plugin_id": PLUGIN_ID, "content": content}, framing, 30))
            print("reload_plugin:", call(sock, {"@": "reload_plugin", "#": "3", "plugin_id": PLUGIN_ID}, framing, 30))
            sock.close()
        print(f"жду {args.wait} с, пока плагин стартует и пройдёт самопроверка…")
        time.sleep(args.wait)
        text = adb("logcat", "-d", "-s", "plugin.stall_doctor:V").stdout
    res = parse_log(text, version)
    print("версия локально:", version, "· на устройстве:", res["ready"])
    print("самопроверка:", res["selfcheck"], "· хуки:", res["hooks"])
    for p in res["problems"]:
        print("ПРОБЛЕМА:", p)
    if not res["problems"]:
        print("OK")
    sys.exit(1 if res["problems"] else 0)


if __name__ == "__main__":
    main()
