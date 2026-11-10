import json
import os
from pathlib import Path
import ssl
import threading

import paho.mqtt.client as mqtt

from .protocol import canonical

DEVICE = "sensor-01"
UP = f"pqc/v1/{DEVICE}/up"
DOWN = f"pqc/v1/{DEVICE}/down"


def auth_key():
    key = Path(os.environ.get("AUTH_KEY_FILE", "runtime/device/auth.key")).read_bytes()
    if len(key) != 32:
        raise ValueError("authentication PSK must have 32 bytes")
    return key


class Transport:
    def __init__(self, name, subscriptions, handler, on_ready=None, will=None):
        self.ready = threading.Event()
        self.error = None
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=name,
                                  protocol=mqtt.MQTTv5)
        credentials = json.loads(Path(os.environ["MQTT_CREDENTIALS"]).read_text())
        self.client.username_pw_set(credentials["username"], credentials["password"])
        context = ssl.create_default_context(cafile=os.environ["MQTT_CA"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.client.tls_set_context(context)
        if will:
            self.client.will_set(will, "offline", qos=1, retain=True)

        def connected(client, userdata, flags, reason_code, properties):
            if reason_code.is_failure:
                self.error = RuntimeError(f"MQTT connection refused: {reason_code}")
                return
            client.subscribe([(topic, 1) for topic in subscriptions])

        def subscribed(client, userdata, mid, reason_codes, properties):
            if any(code.is_failure for code in reason_codes):
                self.error = RuntimeError("MQTT subscription refused")
                return
            self.ready.set()
            if on_ready:
                on_ready()

        def disconnected(client, userdata, flags, reason_code, properties):
            self.ready.clear()

        self.client.on_connect = connected
        self.client.on_subscribe = subscribed
        self.client.on_disconnect = disconnected
        self.client.on_message = lambda client, userdata, msg: handler(msg)
        self.client.reconnect_delay_set(1, 15)

    def start(self):
        self.client.connect(os.environ.get("MQTT_HOST", "localhost"),
                            int(os.environ.get("MQTT_PORT", "8883")), keepalive=30)
        self.client.loop_start()
        if not self.ready.wait(15):
            self.close()
            raise self.error or TimeoutError("MQTT connect/subscribe timeout")
        return self

    def publish(self, topic, payload, retain=False):
        if isinstance(payload, dict):
            payload = canonical(payload)
        info = self.client.publish(topic, payload, qos=1, retain=retain)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise ConnectionError(f"MQTT publish failed: {info.rc}")
        return info

    def close(self):
        self.client.disconnect()
        self.client.loop_stop()
