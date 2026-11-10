"""Primitive microbenchmarks; these are not network or embedded measurements."""

import argparse
import csv
from pathlib import Path
import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import ALGORITHMS, decapsulate, derive_keys, encapsulate, keygen
from .metrics import machine, rss


def run(path, iterations, sizes, warmup=3):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = None
        for algorithm in ALGORITHMS:
            for size in sizes:
                payload = secrets.token_bytes(size)
                for iteration in range(-warmup, iterations):
                    before_rss, cpu_start = rss(), time.process_time_ns()
                    start = time.perf_counter_ns()
                    public, private = keygen(algorithm)
                    a = time.perf_counter_ns()
                    ciphertext, original = encapsulate(algorithm, public)
                    b = time.perf_counter_ns()
                    recovered = decapsulate(algorithm, private, ciphertext)
                    c = time.perf_counter_ns()
                    assert original == recovered
                    up, down = derive_keys(original, secrets.token_bytes(32))
                    d = time.perf_counter_ns()
                    aes = AESGCM(up)
                    nonce = secrets.token_bytes(12)
                    encrypted = aes.encrypt(nonce, payload, b"benchmark")
                    e = time.perf_counter_ns()
                    assert aes.decrypt(nonce, encrypted, b"benchmark") == payload
                    f = time.perf_counter_ns()
                    if iteration < 0:
                        continue
                    private_size = len(private.private_bytes(
                        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )) if algorithm == "x25519" else len(private)
                    row = {"algorithm": algorithm, "iteration": iteration, "payload_bytes": size,
                           "public_key_bytes": len(public), "secret_key_bytes": private_size,
                           "kem_ciphertext_bytes": len(ciphertext),
                           "keygen_ms": (a-start)/1e6, "encaps_ms": (b-a)/1e6,
                           "decaps_ms": (c-b)/1e6, "hkdf_ms": (d-c)/1e6,
                           "encrypt_ms": (e-d)/1e6, "decrypt_ms": (f-e)/1e6,
                           "cpu_ms": (time.process_time_ns()-cpu_start)/1e6,
                           "rss_before_bytes": before_rss, "rss_after_bytes": rss(), **machine()}
                    if writer is None:
                        writer = csv.DictWriter(stream, fieldnames=list(row))
                        writer.writeheader()
                    writer.writerow(row)
                stream.flush()
                print(f"{algorithm}: payload={size}, iterations={iterations}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--sizes", type=int, nargs="+", default=[64, 256, 1024, 4096])
    parser.add_argument("--output", default="results/crypto.csv")
    args = parser.parse_args()
    if args.iterations < 1 or args.warmup < 0 or any(s < 0 or s > 16000 for s in args.sizes):
        parser.error("iterations > 0 and sizes in 0..16000 required")
    run(args.output, args.iterations, args.sizes, args.warmup)
