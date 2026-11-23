import json
import ssl

import pytest

from cryptography import x509

from pqc_iot.provision import provision


def test_provision_is_idempotent_and_separates_credentials(tmp_path):
    root = tmp_path / "runtime"
    provision(root)
    first = (root / "gateway/auth.key").read_bytes()
    assert len(first) == 32
    assert first == (root / "device/auth.key").read_bytes()
    assert not (root / "attacker/auth.key").exists()
    provision(root)
    assert first == (root / "gateway/auth.key").read_bytes()
    accounts = [json.loads((root / name / "mqtt.json").read_text()) for name in
                ("gateway", "device", "homeassistant", "attacker")]
    assert len({a["password"] for a in accounts}) == 4
    cert = x509.load_pem_x509_certificate((root / "broker/server.crt").read_bytes())
    assert "mosquitto" in cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    context = ssl.create_default_context(cafile=str(root / "public/ca.crt"))
    context.load_cert_chain(str(root / "broker/server.crt"), str(root / "broker/server.key"))


def test_compose_precreated_empty_mount_directories(tmp_path):
    root = tmp_path / "runtime"
    (root / "gateway").mkdir(parents=True)
    (root / "broker").mkdir()
    provision(root)
    assert (root / "manifest.json").exists()


def test_existing_provisioning_restores_group_read_access(tmp_path):
    root = tmp_path / "runtime"
    provision(root)
    secret = root / "gateway/mqtt.json"
    secret.chmod(0o600)
    (root / "gateway").chmod(0o700)

    provision(root)

    assert secret.stat().st_mode & 0o040
    assert (root / "gateway").stat().st_mode & 0o050 == 0o050


def test_partial_secrets_are_never_silently_overwritten(tmp_path):
    root = tmp_path / "runtime"
    (root / "device").mkdir(parents=True)
    secret = root / "device/auth.key"
    secret.write_bytes(b"original-key")
    with pytest.raises(RuntimeError):
        provision(root)
    assert secret.read_bytes() == b"original-key"
