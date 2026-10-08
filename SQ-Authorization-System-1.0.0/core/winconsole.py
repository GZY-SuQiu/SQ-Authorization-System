"""Windows 控制台窗口辅助（GUI 模式下隐藏黑色控制台）。

本地服务器是唯一以控制台模式打包的 exe（headless 需要控制台输出）。
双击进入 GUI 时应隐藏控制台，否则界面旁会一直挂着一个黑色窗口。
"""

from __future__ import annotations

import ctypes
import sys

__all__ = ["hide_console_window"]

_SW_HIDE = 0


def _windll():
    """Indirection so tests can fake the Windows DLLs without touching ctypes."""
    return ctypes.windll


def _console_owner_count() -> int:
    """Number of processes attached to this console (0 when there is none)."""
    kernel32 = _windll().kernel32
    buffer = (ctypes.c_uint32 * 8)()
    return int(kernel32.GetConsoleProcessList(buffer, 8))


def hide_console_window() -> bool:
    """Hide this process's console window; return False off Windows/no console.

    只隐藏"这个 exe 独占"的控制台：从 cmd/Windows Terminal 启动时控制台属于
    终端，隐藏它会把用户的终端窗口一起藏起来，这种情况直接跳过。
    """
    if sys.platform != "win32":
        return False
    try:
        if _console_owner_count() > 1:
            return False
        hwnd = _windll().kernel32.GetConsoleWindow()
        if not hwnd:
            return False
        _windll().user32.ShowWindow(hwnd, _SW_HIDE)
        return True
    except Exception:
        return False
