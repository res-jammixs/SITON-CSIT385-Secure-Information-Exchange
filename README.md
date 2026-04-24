# CSIT385 – Secure Information Exchange Program Simulation

## Overview
A Python simulation that securely transmits a message from User A to User B using:
- **Diffie-Hellman Key Exchange** (p=199, g=127) to derive a shared secret
- **AES-128 ECB** encryption with '@' padding for sub-128-bit blocks

## File Structure
```
CSIT385-Secure-Information-Exchange/
├── Constants.py        # DH parameters (p=199, g=127)
├── Diffie_Hellman.py   # Public key & shared secret computation
├── AES_Cipher.py       # Key derivation, encryption, decryption
├── Main.py             # Program entry point / simulation runner
└── README.md           # This file
```

## Requirements
```bash
pip install pycryptodome
```

## Usage
```bash
python Main.py
```

### Example Inputs
| Prompt | Value |
|--------|-------|
| User A private key character | `9` (decimal 57) |
| User B private key character | `§` (decimal 167) |
| Message | `The Mandalorian Must Always Recite, This is The Way!` |

## Algorithm Summary

### 1. Diffie-Hellman
```
Public Key  = g^private mod p
Shared Key  = other_public^own_private mod p
```

### 2. AES-128 Key Derivation
| Shared Secret Digits | Pattern | Example |
|----------------------|---------|---------|
| 1 digit | alternate with 'C' | `1C1C1C1C1C1C1C1C` |
| 2 digits | alternate with 'DD' | `58DD58DD58DD58DD` |
| 3 digits | separate with 'F' | `109F109F109F109F` |

### 3. Message Processing
- Split plaintext into 16-byte chunks
- Pad last chunk with `@` if needed
- Encrypt each chunk independently (AES-128 ECB)
- Concatenate all encrypted chunks → send to User B
- User B decrypts and strips `@` padding
