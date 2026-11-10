"""Bounded injections on the lab's own encrypted topics, using a separate account."""

import argparse
import copy
import json
import queue
import time

from .protocol import canonical, decode, encode, parse
from .transport import DOWN, UP, Transport


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["replay", "tamper", "kem-tamper"], default="replay")
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    incoming = queue.Queue(maxsize=200)

    def receive(msg):
        try:
            incoming.put_nowait((msg.topic, msg.payload))
        except queue.Full:
            pass
    transport = Transport("pqc-lab-attacker", [UP, DOWN], receive)
    try:
        transport.start()
        deadline = time.monotonic() + args.timeout
        target_kind = "exchange" if args.mode == "kem-tamper" else "data"
        packet = None
        while time.monotonic() < deadline:
            try:
                topic, raw = incoming.get(timeout=1)
            except queue.Empty:
                continue
            candidate = parse(raw)
            if topic == UP and candidate.get("kind") == target_kind:
                packet = candidate
                break
        if packet is None:
            raise SystemExit("No matching traffic. Run sensor; kem-tamper requires a new handshake.")
        # Let the genuine record arrive first, then inject a single bounded adversarial packet.
        time.sleep(.5)
        while not incoming.empty():
            incoming.get_nowait()
        forged = copy.deepcopy(packet)
        if args.mode != "replay":
            ciphertext = bytearray(decode(forged["ciphertext"]))
            ciphertext[0] ^= 1
            forged["ciphertext"] = encode(bytes(ciphertext))
            if args.mode == "tamper":
                forged["seq"] += 100000  # AEAD must reject before accepting this sequence.
        transport.publish(UP, canonical(forged)).wait_for_publish(5)
        accepted = False
        until = time.monotonic() + 2
        while time.monotonic() < until:
            try:
                topic, raw = incoming.get(timeout=.2)
            except queue.Empty:
                continue
            message = parse(raw)
            if (topic == DOWN and message.get("sid") == forged["sid"]
                    and message.get("kind") in ("ack", "ready")
                    and message.get("seq") == forged.get("seq", 0)):
                accepted = True
        print(json.dumps({"attack": args.mode, "matching_ack_observed": accepted,
                          "note": "Confirm rejection counter/log in gateway; ACK absence alone is not proof."}))
        if accepted:
            raise SystemExit(1)
    finally:
        transport.close()


if __name__ == "__main__":
    main()
