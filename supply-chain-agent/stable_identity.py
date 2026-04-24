"""Load or create long-term Ed25519 stable identity for Agent Server registration."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from aauth import generate_ed25519_keypair, public_key_to_jwk, calculate_jwk_thumbprint

logger = logging.getLogger(__name__)

STABLE_PRIVATE_NAME = "supply-chain-stable.key"
STABLE_PUBLIC_NAME = "supply-chain-stable.pub"


def _write_private_pem(path: Path, key: Ed25519PrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o600)


def _write_public_pem(path: Path, key: Ed25519PublicKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)
    path.chmod(0o644)


def _load_private_pem(path: Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def _load_public_pem(path: Path) -> Ed25519PublicKey:
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"Expected Ed25519 public key in {path}")
    return key


def load_or_create_stable_identity(keys_dir: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, dict]:
    """Return (stable_priv, stable_pub, stable_pub_jwk). Create key files if missing."""
    priv_path = keys_dir / STABLE_PRIVATE_NAME
    pub_path = keys_dir / STABLE_PUBLIC_NAME

    if priv_path.exists() and pub_path.exists():
        priv = _load_private_pem(priv_path)
        pub = _load_public_pem(pub_path)
        pub_from_priv = priv.public_key()
        if pub_from_priv.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ) != pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ):
            raise ValueError(
                f"Public key {pub_path} does not match private key {priv_path}"
            )
        pub_jwk = public_key_to_jwk(pub)
        jkt = calculate_jwk_thumbprint(pub_jwk)
        logger.info(
            "Loaded stable identity from %s (JKT sha-256: %s)",
            keys_dir,
            jkt,
        )
        logger.info(
            "Stable public JWK (stable_pub wire shape): %s",
            json.dumps(pub_jwk, separators=(",", ":")),
        )
        return priv, pub, pub_jwk

    if priv_path.exists() or pub_path.exists():
        raise FileNotFoundError(
            f"Incomplete stable key material in {keys_dir}: need both "
            f"{STABLE_PRIVATE_NAME} and {STABLE_PUBLIC_NAME} or neither."
        )

    logger.info("Generating new stable identity under %s", keys_dir)
    priv, pub = generate_ed25519_keypair()
    _write_private_pem(priv_path, priv)
    _write_public_pem(pub_path, pub)
    pub_jwk = public_key_to_jwk(pub)
    jkt = calculate_jwk_thumbprint(pub_jwk)
    logger.info(
        "Wrote stable identity %s / %s (JKT sha-256: %s)",
        priv_path,
        pub_path,
        jkt,
    )
    logger.info(
        "Stable public JWK (stable_pub wire shape): %s",
        json.dumps(pub_jwk, separators=(",", ":")),
    )
    return priv, pub, pub_jwk
