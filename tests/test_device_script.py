"""Проверка клиента DevServer на поддельном сервере и разбора лога. Запуск: python3 -I tests/test_device_script.py"""
import json, os, socket, struct, sys, threading
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import device_test as dt


def serve(framing, seen):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    port = srv.getsockname()[1]
    def run():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                while True:
                    if framing == "line":
                        buf = b""
                        while b"\n" not in buf:
                            ch = c.recv(65536)
                            if not ch: raise ConnectionError
                            buf += ch
                        msg = json.loads(buf.split(b"\n")[0])
                    else:
                        n = struct.unpack(">I", dt._recvn(c, 4))[0]; msg = json.loads(dt._recvn(c, n))
                    seen.append(msg)
                    out = json.dumps({"#": msg["#"], "ok": True}).encode()
                    c.sendall(out + b"\n" if framing == "line" else struct.pack(">I", len(out)) + out)
            except Exception:
                c.close()
    threading.Thread(target=run, daemon=True).start()
    return port, srv


for framing in ("line", "len"):
    seen = []
    port, srv = serve(framing, seen)
    sock, used, reply = dt.connect("127.0.0.1", port)
    assert used == framing and reply.get("ok"), (framing, used)
    r = dt.call(sock, {"@": "write_plugin", "#": "2", "plugin_id": "x", "content": "print(1)"}, used)
    assert r["#"] == "2" and any(m["@"] == "write_plugin" for m in seen)
    sock.close(); srv.close()
    print("кадры", framing, "OK")

good = """11-07 10:00:00.000  1  2 I plugin.stall_doctor: [SD] READY version=3.6.0
11-07 10:00:21.000  1  2 I plugin.stall_doctor: [SD] SELFCHECK ok=21 total=22 failed=hook_x
11-07 10:00:21.001  1  2 I plugin.stall_doctor: [SD] HOOKS getDifference=True setIsUpdating=True connection_observer=True"""
r = dt.parse_log(good, "3.6.0"); assert r["ready"] == "3.6.0" and r["selfcheck"] == (21, 22, "hook_x") and not r["problems"], r
bad = good.replace("setIsUpdating=True", "setIsUpdating=False") + "\n11-07 10:00:22.000  1  2 E plugin.stall_doctor: boom"
r = dt.parse_log(bad, "3.6.0"); assert any("хуки" in p for p in r["problems"]) and r["errors"], r
r = dt.parse_log("", "3.6.0"); assert any("READY" in p for p in r["problems"])
r = dt.parse_log(good, "9.9.9"); assert any("версия на устройстве" in p for p in r["problems"])
assert dt.local_version() and dt.local_version().count(".") == 2
print("разбор лога OK")
