import logging
from aauth import generate_ed25519_keypair, public_key_to_jwk

logger = logging.getLogger(__name__)

try:
    _PRIVATE_KEY, _PUBLIC_KEY = generate_ed25519_keypair()
    _PUBLIC_JWK = public_key_to_jwk(_PUBLIC_KEY, kid="market-analysis-agent-ephemeral-1")
    logger.info("🔐 AAuth: Generated ephemeral Ed25519 keypair for agent identity")
except Exception as e:
    _PRIVATE_KEY = _PUBLIC_KEY = _PUBLIC_JWK = None
    logger.error(f"❌ Failed to generate signing keypair at module load: {e}")

def get_signing_keypair():
    if _PRIVATE_KEY is None:
        raise RuntimeError("Signing keypair not initialized")
    return _PRIVATE_KEY, _PUBLIC_KEY, _PUBLIC_JWK
