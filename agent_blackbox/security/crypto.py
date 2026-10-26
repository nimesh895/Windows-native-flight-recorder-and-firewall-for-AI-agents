from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def canonical_json_bytes(data: Any) -> bytes:
    """
    Produces deterministic, canonical JSON encoding:
    sorted keys, no extraneous whitespace, utf-8 encoded.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class KeyManager:
    """
    Manages Ed25519 keys for signing and verifying audit log records.
    """

    def __init__(self, key_dir: str | Path = ".blackbox_keys",
                 private_file: str = "ed25519_private.pem",
                 public_file: str = "ed25519_public.pem"):
        self.key_dir = Path(key_dir)
        self.private_path = self.key_dir / private_file
        self.public_path = self.key_dir / public_file
        self.private_key: ed25519.Ed25519PrivateKey | None = None
        self.public_key: ed25519.Ed25519PublicKey | None = None
        self.load_or_generate()

    def load_or_generate(self) -> None:
        """
        Loads existing Ed25519 keys from disk or generates a new pair.
        """
        self.key_dir.mkdir(parents=True, exist_ok=True)
        if self.private_path.exists() and self.public_path.exists():
            with open(self.private_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.public_path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(f.read())
        else:
            self.generate_keys()

    def generate_keys(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # Save private key
        pem_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.private_path, "wb") as f:
            f.write(pem_private)

        # Save public key
        pem_public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(self.public_path, "wb") as f:
            f.write(pem_public)

        return self.private_key, self.public_key

    def sign(self, data: bytes) -> str:
        """
        Signs arbitrary bytes with the private key.
        Returns the hex-encoded signature.
        """
        if self.private_key is None:
            raise RuntimeError("Private key is not loaded.")
        sig_bytes = self.private_key.sign(data)
        return sig_bytes.hex()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        """
        Verifies signature_hex over data using the public key.
        """
        if self.public_key is None:
            raise RuntimeError("Public key is not loaded.")
        try:
            sig_bytes = bytes.fromhex(signature_hex)
            self.public_key.verify(sig_bytes, data)
            return True
        except Exception:
            return False

    @staticmethod
    def verify_with_public_key_pem(data: bytes, signature_hex: str, public_key_pem: bytes) -> bool:
        """
        Verifies signature using raw public key PEM bytes.
        """
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem)
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key.verify(sig_bytes, data)
            return True
        except Exception:
            return False
