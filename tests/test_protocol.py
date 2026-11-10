import copy
import json
import secrets
import time

from cryptography.exceptions import InvalidTag
import pytest

from pqc_iot.crypto import ALGORITHMS
from pqc_iot.protocol import (ProtocolError, accept_exchange, accept_offer, canonical, decode,
                              encode, hello, make_offer, parse, validate_telemetry)


def pair(algorithm="ml-kem-768"):
    psk = secrets.token_bytes(32)
    request = hello("sensor-01", algorithm, psk)
    offer, private = make_offer(request, psk)
    exchange, client = accept_offer(request, offer, psk)
    gateway = accept_exchange(offer, private, exchange, psk)
    return client, gateway


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_real_kem_handshake_and_both_directions(algorithm):
    client, gateway = pair(algorithm)
    assert client.up == gateway.up and client.down == gateway.down
    assert client.up != client.down
    assert client.open(gateway.seal("ready", 0, {"ready": True}, "down"), "ready", "down")
    packet = client.seal("data", 1, {"temperature": 22})
    assert gateway.open(parse(canonical(packet))) == {"temperature": 22}
    assert client.open(gateway.seal("ack", 1, {"ok": True}, "down"), "ack", "down")


@pytest.mark.parametrize("field", ["public", "algorithm", "nonce", "device", "sid"])
def test_mitm_offer_substitution(field):
    psk = secrets.token_bytes(32)
    request = hello("sensor-01", "ml-kem-768", psk)
    offer, _ = make_offer(request, psk)
    offer[field] = "attacker-controlled-value"
    with pytest.raises(ProtocolError):
        accept_offer(request, offer, psk)


def test_wrong_psk_and_replayed_offer():
    psk = secrets.token_bytes(32)
    first = hello("sensor-01", "hqc-128", psk)
    offer, _ = make_offer(first, psk)
    with pytest.raises(ProtocolError):
        accept_offer(first, offer, secrets.token_bytes(32))
    with pytest.raises(ProtocolError):
        accept_offer(hello("sensor-01", "hqc-128", psk), offer, psk)


def test_replay_and_tamper_do_not_consume_sequence():
    client, gateway = pair()
    packet = client.seal("data", 1, {"test": "value"})
    tampered = copy.deepcopy(packet)
    ciphertext = bytearray(decode(tampered["ciphertext"]))
    ciphertext[0] ^= 1
    tampered["ciphertext"] = encode(bytes(ciphertext))
    with pytest.raises(InvalidTag):
        gateway.open(tampered)
    assert gateway.last_received == -1
    gateway.open(packet)
    with pytest.raises(ProtocolError, match="replay"):
        gateway.open(packet)


@pytest.mark.parametrize("field,value", [("seq", 100), ("device", "other"),
                                        ("sid", "other"), ("direction", "down")])
def test_aad_tamper(field, value):
    client, gateway = pair("x25519")
    packet = client.seal("data", 1, {"test": True})
    packet[field] = value
    with pytest.raises((ProtocolError, InvalidTag)):
        gateway.open(packet)


def test_session_expiry_and_restart():
    client, gateway = pair()
    packet = client.seal("data", 1, {})
    with pytest.raises(ProtocolError, match="expired"):
        gateway.open(packet, now=gateway.created+241)
    _, restarted = pair()
    with pytest.raises(ProtocolError):
        restarted.open(packet)


@pytest.mark.parametrize("sequence", [-1, 2**64, True, 1.5])
def test_invalid_sequence(sequence):
    client, _ = pair("x25519")
    with pytest.raises(ProtocolError):
        client.seal("data", sequence, {})


@pytest.mark.parametrize("payload", [{"temperature": float("nan"), "humidity": 30},
                                     {"temperature": 20, "humidity": 101},
                                     {"temperature": True, "humidity": 30}])
def test_invalid_telemetry(payload):
    with pytest.raises(ProtocolError):
        validate_telemetry({**payload, "ts": time.time()})


def test_oversize_and_invalid_version():
    with pytest.raises(ProtocolError):
        parse(b"x" * 98305)
    with pytest.raises(ProtocolError):
        parse(json.dumps({"v": 2}).encode())
