"""服务端数据库热点操作基准（bug 修复验收工具）。

运行：

    python tools/bench_server.py

构造 500 张许可证 + 200 个设备绑定，测量统计/列表/日志/心跳四类热点操作，
用于确认统计缓存、sweep 节流与索引优化后的实际耗时。
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import security  # noqa: E402
from core.database import Database  # noqa: E402


def _time_it(label: str, iterations: int, action) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        action()
    elapsed = time.perf_counter() - start
    average_ms = elapsed / max(1, iterations) * 1000
    print(f"{label:<28} {iterations:>4} 次  总 {elapsed*1000:>8.1f} ms  平均 {average_ms:>6.2f} ms")
    return elapsed


def main() -> int:
    tmp = tempfile.TemporaryDirectory(prefix="sq_bench_", ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "license.db", "bench-secret")
    try:
        _, keys = db.generate_licenses(count=500, duration_days=30, max_devices=1)
        expiry = security.compute_expiry(30, "day")
        activation_ids = []
        for index, key in enumerate(keys[:200]):
            license = db.get_license(key)
            if not license:
                continue
            result, activation_id, _ = db.activate_atomic(
                license["id"],
                key,
                f"BENCH-MACHINE-{index:04d}",
                f"bench-{index}",
                expiry,
                security.generate_session_secret(),
            )
            if activation_id:
                activation_ids.append(int(activation_id))
        print(f"数据准备：licenses=500, activations={len(activation_ids)}")

        stats_cached = getattr(db, "stats_cached", None)
        if callable(stats_cached):
            _time_it("stats_cached (50x)", 50, stats_cached)
        _time_it("stats (50x)", 50, db.stats)
        _time_it("list_licenses(50)", 200, lambda: db.list_licenses(limit=50))
        _time_it("list_logs(50)", 200, lambda: db.list_logs(limit=50))
        if activation_ids:
            cursor = {"index": 0}

            def _heartbeat() -> None:
                index = cursor["index"] % len(activation_ids)
                cursor["index"] = index + 1
                db.touch_heartbeat(activation_ids[index])

            _time_it("touch_heartbeat", 200, _heartbeat)

        print("基准完成。目标：stats_cached 显著快于 stats；心跳/列表不出现 >100ms 的单次抖动。")
        return 0
    finally:
        db.close()
        tmp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
