"""Versioned, PSK-authenticated handshake and directional AEAD records.

PSKs are provisioned offline. Broker credentials are separate from these keys.
The gateway's fresh offer binds the algorithm, device, client nonce and public key.
"""

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import ALGORITHMS, decapsulate, derive_keys, encapsulate, keygen

MAX_WIRE_BYTES = 98304
MAX_CLOCK_SKEW = 60
SESSION_SECONDS = 240


class ProtocolError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(value):
    return base64.b64decode(value, validate=True)


def parse(raw):
    if len(raw) > MAX_WIRE_BYTES:
        raise ProtocolError("packet too large")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("v") != 1:
        raise ProtocolError("invalid protocol version")
    return value


def sign(body, psk):
    return {**body, "mac": hmac.new(psk, canonical(body), hashlib.sha256).hexdigest()}


def verify(message, psk):
    body = {k: v for k, v in message.items() if k != "mac"}
    expected = hmac.new(psk, canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, message.get("mac", "")):
        raise ProtocolError("handshake authentication failed")
    return body


def fresh(message, now=None):
    now = time.time() if now is None else now
    timestamp = message.get("ts")
    if not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
        raise ProtocolError("invalid timestamp")
    if abs(now - timestamp) > MAX_CLOCK_SKEW:
        raise ProtocolError("expired timestamp")


def hello(device, algorithm, psk):
    if algorithm not in ALGORITHMS:
        raise ProtocolError("unsupported algorithm")
    return sign({"v": 1, "kind": "hello", "device": device, "algorithm": algorithm,
                 "nonce": secrets.token_hex(32), "ts": time.time()}, psk)


def make_offer(request, psk):
    body = verify(request, psk)
    fresh(body)
    if body["kind"] != "hello" or body["algorithm"] not in ALGORITHMS:
        raise ProtocolError("invalid hello")
    if not isinstance(body["nonce"], str) or len(body["nonce"]) != 64:
        raise ProtocolError("invalid client nonce")
    public, private = keygen(body["algorithm"])
    offer = sign({"v": 1, "kind": "offer", "device": body["device"],
                  "algorithm": body["algorithm"], "nonce": body["nonce"],
                  "sid": secrets.token_hex(32), "public": encode(public),
                  "ts": time.time()}, psk)
    return offer, private


@dataclass
class Session:
    device: str
    algorithm: str
    sid: str
    up: bytes
    down: bytes
    created: float
    last_received: int = -1

    def seal(self, kind, sequence, payload, direction="up"):
        if type(sequence) is not int or not 0 <= sequence < 2**64:
            raise ProtocolError("invalid sequence")
        header = {"v": 1, "kind": kind, "device": self.device, "sid": self.sid,
                  "algorithm": self.algorithm, "seq": sequence, "direction": direction}
        key = self.up if direction == "up" else self.down
        nonce = b"\x00" * 4 + sequence.to_bytes(8, "big")
        return {**header, "ciphertext": encode(AESGCM(key).encrypt(
            nonce, canonical(payload), canonical(header)
        ))}

    def open(self, message, kind="data", direction="up", now=None):
        now = time.monotonic() if now is None else now
        if now - self.created > SESSION_SECONDS:
            raise ProtocolError("session expired")
        header = {k: v for k, v in message.items() if k != "ciphertext"}
        if any(header.get(k) != value for k, value in {
            "v": 1, "kind": kind, "device": self.device, "sid": self.sid,
            "algorithm": self.algorithm, "direction": direction,
        }.items()):
            raise ProtocolError("session/header mismatch")
        sequence = header.get("seq")
        if type(sequence) is not int or not 0 <= sequence < 2**64:
            raise ProtocolError("invalid sequence")
        if sequence <= self.last_received:
            raise ProtocolError("replay or out-of-order packet")
        key = self.up if direction == "up" else self.down
        nonce = b"\x00" * 4 + sequence.to_bytes(8, "big")
        plaintext = AESGCM(key).decrypt(nonce, decode(message["ciphertext"]), canonical(header))
        value = json.loads(plaintext)
        if not isinstance(value, dict):
            raise ProtocolError("payload must be an object")
        # Advance only after successful AEAD verification and JSON decoding.
        self.last_received = sequence
        return value


def session_from(secret, offer, exchange):
    digest = hashlib.sha256(canonical({"offer": offer, "exchange": exchange})).digest()
    up, down = derive_keys(secret, digest)
    return Session(offer["device"], offer["algorithm"], offer["sid"], up, down, time.monotonic())


def accept_offer(request, offer, psk):
    body = verify(offer, psk)
    fresh(body)
    for field in ("device", "algorithm", "nonce"):
        if body[field] != request[field]:
            raise ProtocolError("offer not bound to hello")
    if body["kind"] != "offer":
        raise ProtocolError("invalid offer")
    ciphertext, secret = encapsulate(body["algorithm"], decode(body["public"]))
    exchange = sign({"v": 1, "kind": "exchange", "device": body["device"],
                     "sid": body["sid"], "algorithm": body["algorithm"],
                     "ciphertext": encode(ciphertext), "ts": time.time()}, psk)
    return exchange, session_from(secret, offer, exchange)


def accept_exchange(offer, private, exchange, psk):
    body = verify(exchange, psk)
    fresh(body)
    for field in ("device", "algorithm", "sid"):
        if body[field] != offer[field]:
            raise ProtocolError("exchange not bound to offer")
    if body["kind"] != "exchange":
        raise ProtocolError("invalid exchange")
    secret = decapsulate(body["algorithm"], private, decode(body["ciphertext"]))
    return session_from(secret, offer, exchange)


def validate_telemetry(payload):
    fresh(payload)
    for name, low, high in (("temperature", -60, 150), ("humidity", 0, 100)):
        value = payload.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProtocolError(f"invalid {name}")
        if not math.isfinite(value) or not low <= value <= high:
            raise ProtocolError(f"invalid {name}")
    if len(canonical(payload)) > 20000:
        raise ProtocolError("telemetry too large")
