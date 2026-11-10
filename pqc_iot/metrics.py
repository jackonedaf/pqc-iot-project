import csv
import os
from pathlib import Path
import platform
import time

import psutil


def append_csv(filename, row):
    root = Path(os.environ.get("RESULTS_DIR", "results"))
    root.mkdir(parents=True, exist_ok=True)
    path = root / filename
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def machine():
    return {"host": platform.node(), "platform": platform.platform(),
            "python": platform.python_version(), "machine": platform.machine()}


def heartbeat(name):
    path = Path(f"/tmp/{name}.heartbeat" if os.name == "posix" else f".work/{name}.heartbeat")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(time.time()))


def rss():
    return psutil.Process().memory_info().rss
