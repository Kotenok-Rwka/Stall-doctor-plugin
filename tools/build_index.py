#!/usr/bin/env python3
"""Собирает extera-plugins.json (schema 1) из файлов в plugins/.

Метаданные читаются из самих плагинов без их выполнения (ast, только литералы).
  python tools/build_index.py           записать extera-plugins.json
  python tools/build_index.py --check   ничего не писать; код 1, если индекс в репозитории устарел или есть ошибки
"""
import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGINS = ROOT / "plugins"
INDEX = ROOT / "extera-plugins.json"

REPO_NAME = "Stall Doctor"
REPO_AUTHOR = "@Kotenok_Rwka"
REPO_HOMEPAGE = "https://github.com/Kotenok-Rwka/Stall-doctor-plugin"

MAX_PLUGIN_BYTES = 2 * 1024 * 1024       # лимит файла .plugin по документации exteraGram
MAX_INDEX_BYTES = 1024 * 1024            # лимит индекса: 1 МиБ
REQUIRED = ("id", "name", "version", "app_version", "author")
CATEGORIES = {"appearance", "chats", "media", "privacy", "tools", "integrations", "fun", "libraries"}
EXTS = (".py", ".plugin")


def read_meta(path):
    """Дандер-метаданные верхнего уровня как {id: ..., name: ...}; значения только литералы."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    meta = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name.startswith("__") and name.endswith("__"):
                try:
                    meta[name.strip("_")] = ast.literal_eval(node.value)
                except Exception:
                    pass
    return meta


def version_key(v):
    """Числовые части версии: 1.10.0 новее 1.9.2, суффиксы вроде -beta игнорируются."""
    return tuple(int(x) for x in re.findall(r"\d+", str(v).split("-")[0]))


def git_date(path):
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%cI", "--", str(path.relative_to(ROOT))],
                             cwd=ROOT, capture_output=True, text=True, timeout=20).stdout.strip()
        return out or None
    except Exception:
        return None


def build():
    errors, entries = [], {}
    files = sorted(p for p in PLUGINS.iterdir() if p.suffix in EXTS and not p.name.startswith("_"))
    for path in files:
        meta = read_meta(path)
        miss = [k for k in REQUIRED if not meta.get(k)]
        if miss:
            errors.append(f"{path.name}: нет метаданных {', '.join(miss)}")
            continue
        if path.stem != meta["id"]:
            errors.append(f"{path.name}: имя файла должно быть <__id__>{path.suffix}, а __id__ = {meta['id']!r}")
        if not version_key(meta["version"]):
            errors.append(f"{path.name}: версия {meta['version']!r} без числовых частей")
        data = path.read_bytes()
        if len(data) > MAX_PLUGIN_BYTES:
            errors.append(f"{path.name}: {len(data)} байт больше лимита {MAX_PLUGIN_BYTES}")
        cats = meta.get("category", [])
        cats = [cats] if isinstance(cats, str) else list(cats)
        bad = [c for c in cats if c not in CATEGORIES]
        if bad:
            errors.append(f"{path.name}: неизвестные категории {bad}")
        e = {"id": meta["id"], "name": meta["name"], "version": str(meta["version"]),
             "file": path.relative_to(ROOT).as_posix(),
             "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        for src, dst in (("description", "description"), ("author", "author"), ("icon", "icon"),
                         ("app_version", "app_version"), ("sdk_version", "sdk_version"), ("requirements", "requirements")):
            if meta.get(src):
                e[dst] = meta[src]
        if cats:
            e["category"] = cats[:3]
        d = git_date(path)
        if d:
            e["updated_at"] = d
        old = entries.get(e["id"])
        if old is None or version_key(e["version"]) > version_key(old["version"]):
            entries[e["id"]] = e      # по одной записи на плагин: текущая версия
    index = {"schema": 1, "name": REPO_NAME, "author": REPO_AUTHOR, "homepage": REPO_HOMEPAGE,
             "plugins": [entries[k] for k in sorted(entries)]}
    text = json.dumps(index, ensure_ascii=False, indent=2) + "\n"
    if len(text.encode("utf-8")) > MAX_INDEX_BYTES:
        errors.append("индекс больше 1 МиБ")
    return text, errors


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    text, errors = build()
    for e in errors:
        print("ОШИБКА:", e, file=sys.stderr)
    if errors:
        return 1
    if args.check:
        # updated_at зависит от git-истории и в проверку не входит
        strip = lambda s: re.sub(r'\n\s*"updated_at": "[^"]*",?', "", s)
        cur = INDEX.read_text(encoding="utf-8") if INDEX.exists() else ""
        if strip(cur) != strip(text):
            print("extera-plugins.json устарел: запустите python tools/build_index.py", file=sys.stderr)
            return 1
        print("индекс актуален")
        return 0
    INDEX.write_text(text, encoding="utf-8")
    print(f"записано {INDEX.name}: плагинов {len(json.loads(text)['plugins'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
