import logging
import signal
import threading
import time

from cryptography.exceptions import InvalidTag

from .discovery import AVAILABILITY, STATE, publish_discovery
from .metrics import append_csv, heartbeat
from .protocol import (ProtocolError, accept_exchange, canonical, make_offer, parse,
                       validate_telemetry, verify)
from .transport import DEVICE, DOWN, UP, Transport, auth_key

LOG = logging.getLogger("gateway")


class Gateway:
    def __init__(self, psk, publish):
        self.psk = psk
        self.publish = publish
        self.pending = None
        self.session = None
        self.rejected = 0
        self.last_data = 0
        self.last_hello = 0
        self.seen_nonces = {}

    def handle(self, raw):
        message = parse(raw)
        if message.get("device") != DEVICE:
            raise ProtocolError("unknown device")
        now = time.monotonic()
        kind = message.get("kind")
        if kind == "hello":
            verified = verify(message, self.psk)
            self.seen_nonces = {n: t for n, t in self.seen_nonces.items() if now - t < 120}
            nonce = verified["nonce"]
            if nonce in self.seen_nonces or now - self.last_hello < 1:
                raise ProtocolError("replayed or rate-limited hello")
            offer, private = make_offer(message, self.psk)
            self.seen_nonces[nonce] = now
            self.last_hello = now
            self.pending = offer, private, now
            self.publish(DOWN, offer)
        elif kind == "exchange":
            if not self.pending or now - self.pending[2] > 30:
                raise ProtocolError("no live handshake")
            offer, private, _ = self.pending
            session = accept_exchange(offer, private, message, self.psk)
            self.pending = None
            self.session = session
            self.publish(DOWN, session.seal("ready", 0, {"ready": True}, "down"))
            LOG.info("Session established: %s", session.algorithm)
        elif kind == "data":
            if self.session is None:
                raise ProtocolError("no session")
            payload = self.session.open(message)
            validate_telemetry(payload)
            latency = (time.time() - payload["ts"]) * 1000
            state = {"temperature": payload["temperature"], "humidity": payload["humidity"],
                     "algorithm": self.session.algorithm, "payload_bytes": len(raw),
                     "clock_latency_ms": round(latency, 3), "rejected_packets": self.rejected}
            self.publish(STATE, state, retain=True)
            self.publish(AVAILABILITY, "online", retain=True)
            self.publish(DOWN, self.session.seal("ack", message["seq"], {"accepted": True}, "down"))
            self.last_data = now
            append_csv("gateway.csv", {"timestamp": time.time(), "algorithm": self.session.algorithm,
                       "sid": self.session.sid, "sequence": message["seq"], "wire_bytes": len(raw),
                       "plaintext_bytes": len(canonical(payload)), "clock_latency_ms": latency,
                       "rejected_total": self.rejected})
        else:
            raise ProtocolError("unknown message kind")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    gateway = Gateway(auth_key(), lambda *args, **kwargs: transport.publish(*args, **kwargs))

    def ready():
        publish_discovery(transport)
        transport.publish("lab/gateway/status", "online", retain=True)
        transport.publish(AVAILABILITY, "offline", retain=True)

    def receive(msg):
        if msg.topic == "homeassistant/status":
            if msg.payload == b"online":
                publish_discovery(transport)
            return
        try:
            if msg.retain:
                raise ProtocolError("retained protocol message")
            gateway.handle(msg.payload)
        except (ValueError, TypeError, KeyError, OverflowError, InvalidTag) as exc:
            gateway.rejected += 1
            LOG.warning("Rejected packet (%d): %s", gateway.rejected, type(exc).__name__)
    transport = Transport("pqc-gateway", [UP, "homeassistant/status"], receive,
                          on_ready=ready, will="lab/gateway/status")
    try:
        transport.start()
        while not stopped.wait(2):
            if transport.ready.is_set():
                heartbeat("gateway")
                if time.monotonic() - gateway.last_data > 45:
                    transport.publish(AVAILABILITY, "offline", retain=True)
    finally:
        if transport.ready.is_set():
            transport.publish("lab/gateway/status", "offline", retain=True).wait_for_publish(3)
        transport.close()


if __name__ == "__main__":
    main()
