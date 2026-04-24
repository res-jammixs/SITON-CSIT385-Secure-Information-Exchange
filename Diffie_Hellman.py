# Diffie_Hellman.py
# Handles Diffie-Hellman Key Exchange

from Constants import PRIME, GENERATOR


def compute_public_key(private_key: int) -> int:
    """Compute public key using: public = g^private mod p"""
    return pow(GENERATOR, private_key, PRIME)


def compute_shared_secret(other_public_key: int, own_private_key: int) -> int:
    """Compute shared secret using: secret = other_public^own_private mod p"""
    return pow(other_public_key, own_private_key, PRIME)
