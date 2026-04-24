# AES_Cipher.py
# Handles AES-128 Key Derivation, Encryption, and Decryption

from Crypto.Cipher import AES

BLOCK_SIZE = 16   # AES-128 block size in bytes
PAD_CHAR   = '@'  # Padding character


# ---------------------------------------------------------------------------
# Key Derivation
# ---------------------------------------------------------------------------

def derive_key(shared_secret: int) -> bytes:
    """
    Transform the Diffie-Hellman shared secret into a 16-byte (128-bit) AES key.

    Rules:
      - 1 digit  → alternate with 'C'  : "1C1C1C1C1C1C1C1C"
      - 2 digits → alternate with 'DD' : "58DD58DD58DD58DD"
      - 3 digits → separate with 'F'   : "109F109F109F109F"
    """
    s = str(shared_secret)
    digits = len(s)

    if digits == 1:
        pattern = s + 'C'
    elif digits == 2:
        pattern = s + 'DD'
    else:  # 3 digits (shared secret from p=199 is at most 198)
        pattern = s + 'F'

    # Repeat pattern until we have at least 16 characters, then truncate
    repeated = (pattern * ((16 // len(pattern)) + 2))[:16]
    return repeated.encode('ascii')


# ---------------------------------------------------------------------------
# Padding helpers
# ---------------------------------------------------------------------------

def pad(data: bytes) -> bytes:
    """Pad data with '@' characters to reach a multiple of BLOCK_SIZE."""
    remainder = len(data) % BLOCK_SIZE
    if remainder == 0:
        return data
    return data + (PAD_CHAR * (BLOCK_SIZE - remainder)).encode('ascii')


def unpad(data: bytes) -> bytes:
    """Strip trailing '@' padding characters."""
    return data.rstrip(PAD_CHAR.encode('ascii'))


# ---------------------------------------------------------------------------
# Encryption / Decryption
# ---------------------------------------------------------------------------

def encrypt(plaintext: str, key: bytes) -> bytes:
    """
    Encrypt a plaintext string using AES-128 ECB mode.
    The message is padded with '@' and encrypted block-by-block.
    Returns raw ciphertext bytes.
    """
    data = pad(plaintext.encode('ascii'))
    ciphertext = b''
    for i in range(0, len(data), BLOCK_SIZE):
        block  = data[i:i + BLOCK_SIZE]
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext += cipher.encrypt(block)
    return ciphertext


def decrypt(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt AES-128 ECB ciphertext.
    Splits into 16-byte blocks, decrypts each, then strips '@' padding.
    Returns the original plaintext string.
    """
    plaintext = b''
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block  = ciphertext[i:i + BLOCK_SIZE]
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext += cipher.decrypt(block)
    return unpad(plaintext).decode('ascii')
