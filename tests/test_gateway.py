import secrets
import time

import pytest

from pqc_iot.discovery import STATE
from pqc_iot.gateway import Gateway
from pqc_iot.protocol import ProtocolError, accept_offer, canonical, hello


def test_gateway_accepts_once_and_preserves_session_after_forged_exchange(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    published = []
    psk = secrets.token_bytes(32)
    gateway = Gateway(psk, lambda topic, payload, **kw: published.append((topic, payload)))
    request = hello("sensor-01", "ml-kem-768", psk)
    gateway.handle(canonical(request))
    offer = published[-1][1]
    exchange, client = accept_offer(request, offer, psk)
    forged = {**exchange, "ciphertext": "AAAA"}
    with pytest.raises(ProtocolError):
        gateway.handle(canonical(forged))
    gateway.handle(canonical(exchange))
    packet = client.seal("data", 1, {"temperature": 21, "humidity": 40, "ts": time.time()})
    gateway.handle(canonical(packet))
    with pytest.raises(ProtocolError):
        gateway.handle(canonical(packet))
    assert len([p for t, p in published if t == STATE]) == 1
    assert len((tmp_path / "gateway.csv").read_text().splitlines()) == 2
    with pytest.raises(ProtocolError):
        gateway.handle(canonical(request))


def test_unknown_device_and_unestablished_session():
    gateway = Gateway(secrets.token_bytes(32), lambda *a, **kw: None)
    with pytest.raises(ProtocolError):
        gateway.handle(canonical({"v": 1, "kind": "hello", "device": "unknown"}))
    with pytest.raises(ProtocolError):
        gateway.handle(canonical({"v": 1, "kind": "data", "device": "sensor-01"}))
