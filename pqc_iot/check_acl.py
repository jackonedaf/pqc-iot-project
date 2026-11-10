"""Verify that the lab adversary cannot write a Home Assistant state (MQTT v5)."""

import queue

from .discovery import STATE
from .transport import DOWN, Transport


def main():
    results = queue.Queue()
    transport = Transport("pqc-acl-probe", [DOWN], lambda msg: None)

    def published(client, userdata, mid, reason_code, properties):
        results.put(reason_code)
    transport.client.on_publish = published
    try:
        transport.start()
        # Invalid JSON, non-retained: a regression cannot leave a usable fake retained state.
        transport.publish(STATE, b"acl-probe")
        result = results.get(timeout=10)
        if result.value != 0x87:
            raise SystemExit(f"Expected Not authorized (0x87), got {result}")
        print("PASS: attacker publication to verified HA state denied by broker (0x87).")
    finally:
        transport.close()


if __name__ == "__main__":
    main()
