"""Заглушки модулей exteraGram SDK: плагин можно загрузить и проверить без телефона."""
import importlib.machinery
import importlib.util
import pathlib
import sys
import types
from unittest.mock import MagicMock

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "stall_doctor.py"


class Stub(types.ModuleType):
    def __getattr__(self, n):
        if n.startswith("__"):
            raise AttributeError(n)
        m = MagicMock(name=n)
        setattr(self, n, m)
        return m


class BasePlugin:
    def get_setting(self, k, d=None):
        return self.__dict__.setdefault("_set", {}).get(k, d)

    def set_setting(self, k, v, **kw):
        self.__dict__.setdefault("_set", {})[k] = v


_NAMES = ["client_utils", "android_utils", "base_plugin", "file_utils", "hook_utils", "java", "org", "org.telegram",
          "org.telegram.messenger", "org.telegram.tgnet", "ui", "ui.alert", "ui.bulletin", "ui.settings"]


def install():
    for name in _NAMES:
        sys.modules[name] = Stub(name)
    sys.modules["base_plugin"].BasePlugin = BasePlugin
    sys.modules["android_utils"].run_on_ui_thread = lambda f: f()


def load(tag="sd"):
    """Свежий экземпляр модуля плагина (глобальные заглушки ставятся заново)."""
    install()
    loader = importlib.machinery.SourceFileLoader(tag, str(PLUGIN))
    spec = importlib.util.spec_from_loader(tag, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Checker:
    """Собирает проверки со сводкой: тест падает один раз и показывает все сломанные пункты."""

    def __init__(self):
        self.fails = []
        self.total = 0

    def __call__(self, name, cond, extra=""):
        self.total += 1
        print(("PASS " if cond else "FAIL ") + name + (" " + str(extra) if extra else ""))
        if not cond:
            self.fails.append(f"{name} {extra}".strip())
