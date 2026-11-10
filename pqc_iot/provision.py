"""Idempotent local provisioning. Never print passwords or authentication keys."""

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def write(path, data, mode=0o600, uid=10001):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(mode)
    if os.name == "posix" and os.geteuid() == 0:
        os.chown(path, uid, uid)


def password_hash(password):
    salt = secrets.token_bytes(12)
    iterations = 101000
    digest = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations)
    return f"$7${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def provision(root):
    root = Path(root)
    manifest = root / "manifest.json"
    if manifest.exists():
        for relative in json.loads(manifest.read_text())["files"]:
            if not (root / relative).is_file():
                raise RuntimeError(f"Incomplete provisioning: missing {relative}; restore runtime backup")
        print("Provisioning already complete; existing identities preserved.")
        return
    # Compose can create empty bind-mount directories before the init service starts.
    if root.exists() and any(p.is_file() for p in root.rglob("*")):
        raise RuntimeError("Nonempty runtime without manifest; inspect interrupted provisioning first")
    root.mkdir(parents=True, exist_ok=True)
    for name in ("gateway", "device", "homeassistant", "attacker", "broker", "public", "ca"):
        folder = root / name
        folder.mkdir(exist_ok=True)
        folder.chmod(0o755 if name in ("broker", "public") else 0o700)
        if os.name == "posix" and os.geteuid() == 0:
            owner = 1883 if name == "broker" else 10001
            os.chown(folder, owner, owner)
    psk = secrets.token_bytes(32)
    for name in ("gateway", "device"):
        write(root / name / "auth.key", psk)
    passwords = []
    for folder, username in (("gateway", "gateway"), ("device", "sensor-01"),
                             ("homeassistant", "homeassistant"), ("attacker", "attacker"),
                             ("broker", "healthcheck")):
        password = secrets.token_urlsafe(32)
        passwords.append(f"{username}:{password_hash(password)}")
        if username == "healthcheck":
            write(root / folder / "healthcheck.password", password + "\n", uid=1883)
            # CLI config allows a healthcheck without passwords in argv.
            write(root / folder / "mosquitto_pub", f"-u healthcheck\n-P {password}\n", uid=1883)
        else:
            write(root / folder / "mqtt.json", json.dumps({"username": username, "password": password}))
    write(root / "broker/passwords", "\n".join(passwords) + "\n", uid=1883)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PQC IoT Lab CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                         critical=True)
          .sign(ca_key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mosquitto")]))
            .issuer_name(ca_name).public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("mosquitto"), x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256()))
    for path, key, uid in (("ca/ca.key", ca_key, 10001), ("broker/server.key", server_key, 1883)):
        write(root / path, key.private_bytes(serialization.Encoding.PEM,
              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), uid=uid)
    for path in ("public/ca.crt", "broker/ca.crt"):
        write(root / path, ca.public_bytes(serialization.Encoding.PEM), mode=0o644, uid=1883)
    write(root / "broker/server.crt", cert.public_bytes(serialization.Encoding.PEM), 0o644, 1883)
    files = sorted(str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*") if p.is_file())
    write(manifest, json.dumps({"version": 1, "files": files}, indent=2))
    results = root.parent / "results"
    results.mkdir(exist_ok=True)
    if os.name == "posix" and os.geteuid() == 0:
        os.chown(results, 10001, 10001)
    print("Provisioned TLS, MQTT accounts and device PSK. Secrets are in runtime/ (gitignored).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="runtime")
    provision(parser.parse_args().root)
