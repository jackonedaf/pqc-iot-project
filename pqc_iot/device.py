import argparse
import logging
import os
import queue
import random
import secrets
import signal
import threading
import time

from cryptography.exceptions import InvalidTag

from .crypto import ALGORITHMS
from .metrics import append_csv, heartbeat, rss
from .protocol import ProtocolError, accept_offer, canonical, hello, parse
from .transport import DEVICE, DOWN, UP, Transport, auth_key

LOG = logging.getLogger("sensor")


class Device:
    def __init__(self, algorithm, incoming, transport, psk, timeout=10):
        self.algorithm, self.incoming, self.transport, self.psk = algorithm, incoming, transport, psk
        self.timeout = timeout
        self.session = None
        self.sequence = 0
        self.handshake_ms = 0

    def wait(self, kind, validate):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                raw = self.incoming.get(timeout=max(0.001, deadline - time.monotonic()))
            except queue.Empty:
                break
            try:
                message = parse(raw)
                if message.get("kind") != kind:
                    continue
                return validate(message)
            except (ValueError, TypeError, KeyError, OverflowError, InvalidTag):
                LOG.warning("Ignored invalid %s response", kind)
        raise TimeoutError(f"No authenticated {kind} response")

    def handshake(self):
        started = time.perf_counter()
        request = hello(DEVICE, self.algorithm, self.psk)
        self.transport.publish(UP, request)
        exchange, session = self.wait("offer", lambda msg: accept_offer(request, msg, self.psk))
        self.transport.publish(UP, exchange)
        self.wait("ready", lambda msg: session.open(msg, "ready", "down"))
        self.session, self.sequence = session, 0
        self.handshake_ms = (time.perf_counter() - started) * 1000
        LOG.info("Authenticated %s session; handshake %.2f ms", self.algorithm, self.handshake_ms)

    def send(self, padding):
        if self.session is None or time.monotonic() - self.session.created > 180:
            self.handshake()
        self.sequence += 1
        payload = {"temperature": round(22 + random.uniform(-2, 2), 2),
                   "humidity": round(45 + random.uniform(-5, 5), 2), "ts": time.time(),
                   "padding": "x" * padding}
        started, cpu = time.perf_counter(), time.process_time()
        packet = self.session.seal("data", self.sequence, payload)
        self.transport.publish(UP, packet)

        def acknowledge(message):
            if message.get("seq") != self.sequence:
                raise ProtocolError("ack sequence mismatch")
            return self.session.open(message, "ack", "down")
        self.wait("ack", acknowledge)
        return {"timestamp": time.time(), "algorithm": self.algorithm, "sid": self.session.sid,
                "sequence": self.sequence, "padding_bytes": padding,
                "wire_bytes": len(canonical(packet)), "rtt_ms": (time.perf_counter() - started)*1000,
                "cpu_ms": (time.process_time() - cpu)*1000, "rss_bytes": rss(),
                "handshake_ms": self.handshake_ms, "status": "ok"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--algorithm", choices=ALGORITHMS, default=os.getenv("ALGORITHM", "ml-kem-768"))
    parser.add_argument("--interval", type=float, default=float(os.getenv("PUBLISH_INTERVAL", "5")))
    parser.add_argument("--count", type=int, default=0, help="0 = continuous")
    parser.add_argument("--padding", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.padding <= 16000 or args.interval < 0 or args.count < 0:
        parser.error("padding must be 0..16000, interval/count >= 0")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    incoming = queue.Queue(maxsize=100)
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())

    def receive(msg):
        if msg.retain:
            return
        try:
            incoming.put_nowait(msg.payload)
        except queue.Full:
            pass
    transport = Transport(f"pqc-sensor-{secrets.token_hex(4)}", [DOWN], receive)
    failures = 0
    try:
        transport.start()
        device = Device(args.algorithm, incoming, transport, auth_key())
        count = 0
        run_id = secrets.token_hex(8)
        while not stopped.is_set() and (not args.count or count < args.count):
            try:
                row = device.send(args.padding)
                heartbeat("sensor")
                LOG.info("Telemetry acknowledged; RTT %.2f ms", row["rtt_ms"])
            except (TimeoutError, ConnectionError, OSError) as exc:
                failures += 1
                device.session = None
                LOG.warning("Retry with fresh session: %s", exc)
                row = {"timestamp": time.time(), "algorithm": args.algorithm, "sid": "",
                       "sequence": "", "padding_bytes": args.padding, "wire_bytes": "",
                       "rtt_ms": "", "cpu_ms": "", "rss_bytes": rss(),
                       "handshake_ms": "", "status": "timeout"}
            append_csv(f"device-{run_id}.csv", row)
            count += 1
            stopped.wait(max(1 if row["status"] != "ok" else 0, args.interval))
    finally:
        transport.close()
    if args.count and failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
