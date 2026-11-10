import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path
import statistics

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def percentile(values, p):
    ordered = sorted(values)
    position = (len(ordered) - 1) * p
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def generate(root):
    root = Path(root)
    summary = {}
    path = root / "crypto.csv"
    if path.exists():
        groups = defaultdict(list)
        with path.open(encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                groups[(row["algorithm"], row["payload_bytes"])].append(row)
        labels, values = [], []
        for (algorithm, size), rows in groups.items():
            times = [sum(float(r[k]) for k in ("keygen_ms", "encaps_ms", "decaps_ms")) for r in rows]
            key = f"{algorithm}/{size}B"
            summary[key] = {"samples": len(times), "kem_mean_ms": statistics.mean(times),
                            "kem_median_ms": statistics.median(times), "kem_p95_ms": percentile(times, .95)}
            labels.append(key)
            values.append(statistics.mean(times))
        fig, ax = plt.subplots(figsize=(12, 5))
        ax.bar(labels, values)
        ax.set_ylabel("Total KEM time [ms]")
        ax.set_title("Mean key generation + encapsulation + decapsulation")
        ax.tick_params(axis="x", labelrotation=55)
        fig.tight_layout()
        fig.savefig(root / "kem-comparison.png", dpi=180)
        plt.close(fig)
    groups = defaultdict(list)
    for path in root.glob("device-*.csv"):
        with path.open(encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                groups[(row["algorithm"], row["padding_bytes"])].append(row)
    labels, rtts = [], []
    for (algorithm, padding), rows in groups.items():
        good = [float(r["rtt_ms"]) for r in rows if r["status"] == "ok"]
        key = f"network/{algorithm}/padding-{padding}B"
        result = {"attempts": len(rows), "acknowledged": len(good),
                  "unacknowledged_ratio": 1-len(good)/len(rows)}
        if good:
            result.update(rtt_mean_ms=statistics.mean(good), rtt_median_ms=statistics.median(good),
                          rtt_p95_ms=percentile(good, .95))
            labels.append(f"{algorithm}/{padding}B")
            rtts.append(good)
        summary[key] = result
    if rtts:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.boxplot(rtts, tick_labels=labels, showfliers=True)
        ax.set_ylabel("Authenticated application ACK round trip [ms]")
        ax.tick_params(axis="x", labelrotation=45)
        fig.tight_layout()
        fig.savefig(root / "network-rtt.png", dpi=180)
        plt.close(fig)
    if not summary:
        raise SystemExit("No measurement CSV files found; run benchmark or sensor first")
    (root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", default="results")
    generate(parser.parse_args().results)
