"""Индекс каталога: метаданные плагинов корректны, индекс в репозитории соответствует файлам."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import build_index  # noqa: E402


def test_build_has_no_errors():
    text, errors = build_index.build()
    assert not errors, errors
    assert json.loads(text)["schema"] == 1


def test_committed_index_is_current():
    assert build_index.main(["--check"]) == 0


def test_entries_match_files():
    data = json.loads((ROOT / "extera-plugins.json").read_text(encoding="utf-8"))
    ids = set()
    for e in data["plugins"]:
        raw = (ROOT / e["file"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == e["sha256"]
        assert len(raw) == e["size"]
        assert e["id"] not in ids
        ids.add(e["id"])
        meta = build_index.read_meta(ROOT / e["file"])
        assert meta["id"] == e["id"] and str(meta["version"]) == e["version"]


def test_version_order():
    k = build_index.version_key
    assert k("1.10.0") > k("1.9.2") and k("3.9.0-beta") == (3, 9, 0)
