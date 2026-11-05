"""Scan rendered screenshots for suspicious long dark bars.

A "thick vertical bar" defect (unstyled splitter handle, stray QFrame
separator, or a black scrollbar) shows up as a column of dark pixels that
spans most of the image.  This tool reports those runs so UI regressions
can be caught without eyeballing every screenshot.

Usage:
    python tools/visual_check.py build/shots [--max-dark 120] [--min-run 60]
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np
from PIL import Image


def _longest_runs(mask: np.ndarray, axis: int, max_gap: int = 1) -> np.ndarray:
    """Return the longest run of True values along ``axis`` for each line.

    A run may jump over at most ``max_gap`` False pixels so that a dashed
    handle or a 1px anti-aliased seam is still reported.
    """
    if axis == 0:
        mask = mask.T
    height, width = mask.shape
    best = np.zeros(height, dtype=np.int32)
    for row in range(height):
        line = mask[row]
        run = 0
        gap = 0
        for value in line:
            if value:
                run += gap + 1
                gap = 0
            else:
                gap += 1
                if gap > max_gap:
                    run = 0
                    gap = 0
            if run > best[row]:
                best[row] = run
    return best


def scan(path: str, max_dark: int = 120, min_run: int = 60) -> list[dict]:
    image = Image.open(path).convert("RGB")
    # int16 overflows on 255 * 299 and would mark every pixel as dark.
    array = np.asarray(image).astype(np.int32)
    luma = (array[:, :, 0] * 299 + array[:, :, 1] * 587 + array[:, :, 2] * 114) // 1000
    mask = luma <= max_dark
    height, width = mask.shape
    findings: list[dict] = []

    col_runs = _longest_runs(mask, axis=0)
    row_runs = _longest_runs(mask, axis=1)

    def collect(runs: np.ndarray, kind: str, limit: int) -> None:
        hot = np.where(runs >= limit)[0]
        if not hot.size:
            return
        start = hot[0]
        previous = hot[0]
        for index in list(hot[1:]) + [hot[-1] + 2]:
            if index != previous + 1:
                block = hot[(hot >= start) & (hot <= previous)]
                local = runs[block]
                findings.append(
                    {
                        "kind": kind,
                        "start": int(start),
                        "end": int(previous),
                        "thickness": int(previous - start + 1),
                        "run": int(local.max()),
                        "limit": int(limit),
                        "ratio": round(float(local.max()) / (height if kind == "vertical" else width), 3),
                    }
                )
                start = index
            previous = index

    collect(col_runs, "vertical", min_run)
    collect(row_runs, "horizontal", min_run)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--max-dark", type=int, default=120)
    parser.add_argument("--min-run", type=int, default=60)
    parser.add_argument("--ratio", type=float, default=0.35, help="run / dimension threshold to report")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"not a directory: {args.directory}")
        return 2

    total = 0
    for name in sorted(os.listdir(args.directory)):
        if not name.lower().endswith(".png"):
            continue
        path = os.path.join(args.directory, name)
        for finding in scan(path, args.max_dark, args.min_run):
            if finding["ratio"] < args.ratio:
                continue
            total += 1
            print(
                f"{name}: {finding['kind']} bar at {finding['start']}..{finding['end']}"
                f" thickness={finding['thickness']}px run={finding['run']}px"
                f" coverage={finding['ratio'] * 100:.0f}%"
            )
    if total == 0:
        print("clean: no long dark bars found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
