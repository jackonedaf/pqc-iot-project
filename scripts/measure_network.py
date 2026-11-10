"""Serial algorithm/payload matrix against an already running Compose laboratory."""

import argparse
import subprocess

ALGORITHMS = ("ml-kem-768", "hqc-128", "x25519")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--interval", type=float, default=.1)
    parser.add_argument("--sizes", type=int, nargs="+", default=[0, 256, 1024, 4096])
    args = parser.parse_args()
    if args.count < 1 or args.interval < 0 or any(s < 0 or s > 16000 for s in args.sizes):
        parser.error("count > 0, interval >= 0, sizes in 0..16000 required")
    subprocess.run(["docker", "compose", "stop", "sensor"], check=True)
    try:
        for algorithm in ALGORITHMS:
            for size in args.sizes:
                subprocess.run([
                    "docker", "compose", "run", "--rm", "--no-deps", "sensor",
                    "python", "-m", "pqc_iot.device", "--algorithm", algorithm,
                    "--padding", str(size), "--count", str(args.count),
                    "--interval", str(args.interval),
                ], check=True)
    finally:
        subprocess.run(["docker", "compose", "up", "-d", "--no-deps", "sensor"], check=True)


if __name__ == "__main__":
    main()
