STATE = "lab/verified/sensor-01/state"
AVAILABILITY = "lab/verified/sensor-01/availability"

SENSORS = {
    "temperature": ("Temperature", "°C", "temperature"),
    "humidity": ("Humidity", "%", "humidity"),
    "algorithm": ("Algorithm", None, None),
    "payload_bytes": ("Payload bytes", "B", None),
    "clock_latency_ms": ("Clock latency ms", "ms", None),
    "rejected_packets": ("Rejected packets", None, None),
}


def publish_discovery(transport):
    for key, (name, unit, device_class) in SENSORS.items():
        payload = {
            "name": name, "unique_id": f"pqc_{key}", "default_entity_id": f"sensor.pqc_{key}",
            "state_topic": STATE, "value_template": "{{ value_json." + key + " }}",
            "availability": [{"topic": "lab/gateway/status"}, {"topic": AVAILABILITY}],
            "availability_mode": "all", "expire_after": 60,
            "device": {"identifiers": ["pqc_sensor_01"], "name": "PQC sensor",
                       "manufacturer": "PQC IoT Lab", "model": "MQTT authenticated gateway"},
        }
        if unit:
            payload["unit_of_measurement"] = unit
        if device_class:
            payload["device_class"] = device_class
        if key not in ("algorithm", "rejected_packets"):
            payload["state_class"] = "measurement"
        transport.publish(f"homeassistant/sensor/pqc_sensor_01/{key}/config", payload, retain=True)
