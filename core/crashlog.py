"""全局崩溃日志：未捕获异常、线程异常与 Qt 警告写入 crash_logs/。

PySide6 对槽函数里未处理的异常行为随版本变化，最坏情况会直接终止应用。
四个入口都调用 ``install()``：

- sys.excepthook：记录主线程未捕获异常，记录后继续事件循环；
- threading.excepthook：记录工作线程异常（邮件/渠道/告警/心跳）；
- faulthandler：致命错误（段错误等）也能留下栈；
- Qt message handler：把 Qt 的 warning/critical 一并落盘。

日志目录在程序目录下的 ``crash_logs/``；目录不可写时静默跳过，绝不反过来
影响程序启动。
"""

from __future__ import annotations

import faulthandler
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path

__all__ = ["install", "log_exception", "log_text", "log_dir"]

_installed = False


def log_dir() -> Path:
    try:
        from .config import app_dir

        base = app_dir()
    except Exception:
        base = Path.cwd()
    path = Path(base) / "crash_logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_text(kind: str, text: str) -> None:
    try:
        path = log_dir() / f"crash-{datetime.now():%Y%m%d}.log"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                f"\n===== {datetime.now():%Y-%m-%d %H:%M:%S} [{kind}] =====\n"
                f"{text}\n"
            )
    except Exception:
        pass


def log_exception(kind: str, exc: BaseException) -> None:
    log_text(
        kind,
        "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
    )


def install(app_name: str = "SQ-Authorization") -> None:
    """Install process-wide handlers; safe to call multiple times."""
    global _installed
    if _installed:
        return
    _installed = True

    try:
        faulthandler.enable()
    except Exception:
        pass

    def _excepthook(exc_type, exc, tb):
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        log_text(f"unhandled:{app_name}", text)
        try:
            print(text, file=sys.stderr)
        except Exception:
            pass
        # 记录后返回：Qt 槽函数异常不再向上冒泡终止事件循环。

    sys.excepthook = _excepthook

    def _thread_hook(args):
        name = args.thread.name if args.thread is not None else "unknown"
        text = "".join(
            traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)
        )
        log_text(f"thread:{name}", text)

    threading.excepthook = _thread_hook

    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler

        def _qt_handler(mode, context, message):
            if mode in (
                QtMsgType.QtWarningMsg,
                QtMsgType.QtCriticalMsg,
                QtMsgType.QtFatalMsg,
            ):
                location = ""
                try:
                    location = f"{context.file}:{context.line} "
                except Exception:
                    pass
                log_text(f"qt:{mode}", f"{location}{message}")

        qInstallMessageHandler(_qt_handler)
    except Exception:
        pass
