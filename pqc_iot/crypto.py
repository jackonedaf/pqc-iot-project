"""Real KEM implementations; X25519 is the classical reference."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import hqc_128, ml_kem_768

ALGORITHMS = ("ml-kem-768", "hqc-128", "x25519")
MODULES = {"ml-kem-768": ml_kem_768, "hqc-128": hqc_128}


def keygen(algorithm):
    if algorithm == "x25519":
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return public, private
    return MODULES[algorithm].generate_keypair()


def encapsulate(algorithm, public):
    if algorithm == "x25519":
        ephemeral = X25519PrivateKey.generate()
        ciphertext = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return ciphertext, ephemeral.exchange(X25519PublicKey.from_public_bytes(public))
    return MODULES[algorithm].encrypt(public)


def decapsulate(algorithm, private, ciphertext):
    if algorithm == "x25519":
        return private.exchange(X25519PublicKey.from_public_bytes(ciphertext))
    return MODULES[algorithm].decrypt(private, ciphertext)


def derive_keys(secret, transcript_hash):
    material = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=transcript_hash,
        info=b"pqc-iot/v1/aes-256-gcm/up+down",
    ).derive(secret)
    return material[:32], material[32:]
