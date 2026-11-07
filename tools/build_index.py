#!/usr/bin/env python3
"""Собирает extera-plugins.json (schema 1) из плагинов в plugins/ и проверяет метаданные.
Метаданные читаются статически через ast, плагин не исполняется.
Запуск: python3 -I tools/build_index.py [--name "Название"] [--check]"""
import argparse, ast, hashlib, json, os, re, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGINS = os.path.join(ROOT, "plugins")
EXT = (".py", ".plugin")
CATEGORIES = {"appearance", "chats", "media", "privacy", "tools", "integrations", "fun", "libraries"}
ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{1,31}$")
MAX_PLUGIN = 2 * 1024 * 1024
MAX_INDEX = 1024 * 1024
FIELDS = {"__id__": "id", "__name__": "name", "__description__": "description", "__author__": "author", "__version__": "version",
          "__icon__": "icon", "__app_version__": "app_version", "__sdk_version__": "sdk_version",
          "__requirements__": "requirements", "__category__": "category"}


def read_meta(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    meta = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name.startswith("__") and name.endswith("__"):
                try:
                    meta[name] = ast.literal_eval(node.value)
                except Exception:
                    meta[name + "!dynamic"] = True
    return meta


def build(name):
    problems, plugins = [], []
    for fn in sorted(os.listdir(PLUGINS)):
        if not fn.endswith(EXT):
            continue
        path = os.path.join(PLUGINS, fn)
        data = open(path, "rb").read()
        meta = read_meta(path)
        pid = meta.get("__id__")
        if not isinstance(pid, str) or not ID_RE.match(pid):
            problems.append(f"{fn}: недопустимый __id__ {pid!r}")
            continue
        if os.path.splitext(fn)[0] != pid:
            problems.append(f"{fn}: имя файла должно совпадать с __id__ ({pid})")
        for k in meta:
            if k.endswith("!dynamic"):
                problems.append(f"{fn}: {k[:-8]} задан не литералом, движок читает метаданные статически")
        if "__min_version__" in meta:
            problems.append(f"{fn}: __min_version__ устарел, используйте __app_version__")
        if not isinstance(meta.get("__name__"), str):
            problems.append(f"{fn}: нет __name__")
        if len(data) > MAX_PLUGIN:
            problems.append(f"{fn}: {len(data)} байт, лимит {MAX_PLUGIN} для .plugin")
        cats = meta.get("__category__")
        cats = [cats] if isinstance(cats, str) else (cats or [])
        if len(cats) > 3 or any(c not in CATEGORIES for c in cats):
            problems.append(f"{fn}: __category__ допускает до 3 значений из {sorted(CATEGORIES)}")
        entry = {"id": pid, "name": meta.get("__name__", pid), "version": str(meta.get("__version__", "1.0")),
                 "file": "plugins/" + fn, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                 "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(path)))}
        for key, out in FIELDS.items():
            if key in meta and out not in entry and out != "category":
                entry[out] = meta[key]
        if cats:
            entry["category"] = cats if len(cats) > 1 else cats[0]
        plugins.append(entry)
    index = {"schema": 1, "name": name, "plugins": plugins}
    raw = json.dumps(index, ensure_ascii=False, indent=2) + "\n"
    if len(raw.encode("utf-8")) > MAX_INDEX:
        problems.append("индекс больше 1 МиБ")
    return raw, problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="Stall Doctor")
    ap.add_argument("--check", action="store_true", help="только проверить, индекс не писать")
    args = ap.parse_args()
    raw, problems = build(args.name)
    for p in problems:
        print("ПРОБЛЕМА:", p, file=sys.stderr)
    if problems:
        sys.exit(1)
    if not args.check:
        with open(os.path.join(ROOT, "extera-plugins.json"), "w", encoding="utf-8") as f:
            f.write(raw)
    print("OK: плагинов в индексе:", json.loads(raw)["plugins"].__len__())


if __name__ == "__main__":
    main()
