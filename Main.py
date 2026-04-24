# Main.py
# Secure Information Exchange Program Simulation
# Combines Diffie-Hellman key exchange with AES-128 encryption

from Constants       import PRIME, GENERATOR
from Diffie_Hellman  import compute_public_key, compute_shared_secret
from AES_Cipher      import derive_key, encrypt, decrypt, BLOCK_SIZE, PAD_CHAR

DIVIDER = "=" * 50
SECTION = "-" * 50


def print_header():
    print(DIVIDER)
    print("  SECURE INFORMATION EXCHANGE PROGRAM SIMULATION")
    print("         Diffie-Hellman (p=199, g=127) + AES-128")
    print(DIVIDER)


def get_private_key(user_label: str) -> int:
    """Prompt the user to enter a single ASCII character as the private key."""
    while True:
        raw = input(f"\nEnter User {user_label}'s private key character "
                    f"(e.g., '9' for decimal 57): ")
        if len(raw) == 1:
            return ord(raw)
        print("  [!] Please enter exactly ONE character.")


def main():
    print("\nWelcome to the Secure Information Exchange Program Simulation")
    print("Using: Diffie-Hellman (p=199, g=127) + AES-128\n")

    # -----------------------------------------------------------------------
    # Step 1 – Private Keys
    # -----------------------------------------------------------------------
    priv_a = get_private_key("A")
    priv_b_raw = input(f"Enter User B's private key character: ")
    priv_b = ord(priv_b_raw[0]) if priv_b_raw else 167

    message = input("Enter the message to send from User A to User B: ")

    print(f"\n{DIVIDER}")
    print("  SECURE INFORMATION EXCHANGE PROGRAM SIMULATION")
    print(f"  Diffie-Hellman (p={PRIME}, g={GENERATOR}) + AES-128")
    print(DIVIDER)

    print(f"\n{SECTION}")
    print("  STEP 1 – Private Keys")
    print(SECTION)
    print(f"  User A  char='{chr(priv_a)}'  decimal={priv_a:>3}  "
          f"binary={priv_a:08b}  hex={priv_a:02X}")
    print(f"  User B  char='{chr(priv_b)}'  decimal={priv_b:>3}  "
          f"binary={priv_b:08b}  hex={priv_b:02X}")

    # -----------------------------------------------------------------------
    # Step 2 – Public Keys  (g^private mod p)
    # -----------------------------------------------------------------------
    pub_a = compute_public_key(priv_a)
    pub_b = compute_public_key(priv_b)

    print(f"\n{SECTION}")
    print("  STEP 2 – Public Values (g^priv mod p)")
    print(SECTION)
    print(f"  User A  Public Value = {GENERATOR}^{priv_a} mod {PRIME} = {pub_a}")
    print(f"  User B  Public Value = {GENERATOR}^{priv_b} mod {PRIME} = {pub_b}")

    # -----------------------------------------------------------------------
    # Step 3 – Shared Secret
    # -----------------------------------------------------------------------
    secret_a = compute_shared_secret(pub_b, priv_a)
    secret_b = compute_shared_secret(pub_a, priv_b)

    print(f"\n{SECTION}")
    print("  STEP 3 – Shared Secret")
    print(SECTION)
    print(f"  From A's side: {pub_b}^{priv_a} mod {PRIME} = {secret_a}")
    print(f"  From B's side: {pub_a}^{priv_b} mod {PRIME} = {secret_b}")
    assert secret_a == secret_b, "Shared secrets do not match!"
    print(f"  ✓ Shared Secret = {secret_a}")

    # -----------------------------------------------------------------------
    # Step 4 – AES-128 Key Derivation
    # -----------------------------------------------------------------------
    aes_key = derive_key(secret_a)

    print(f"\n{SECTION}")
    print("  STEP 4 – AES-128 Key Derivation")
    print(SECTION)
    print(f"  Shared secret integer : {secret_a}")
    print(f"  AES-128 key (hex)     : {aes_key.hex().upper()}")
    print(f"  AES-128 key (ascii)   : {aes_key.decode()}")

    # -----------------------------------------------------------------------
    # Step 5 – Message Chunking & Padding
    # -----------------------------------------------------------------------
    msg_bytes = message.encode('ascii')
    num_chunks = (len(msg_bytes) + BLOCK_SIZE - 1) // BLOCK_SIZE

    print(f"\n{SECTION}")
    print("  STEP 5 – Message Chunking & Padding")
    print(SECTION)
    print(f"  Message : \"{message}\"")
    print(f"  Length  : {len(message)} chars = {num_chunks} chunk(s) × 16 bytes\n")

    chunks = []
    for i in range(num_chunks):
        raw   = message[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE]
        padded = raw.ljust(BLOCK_SIZE, PAD_CHAR)
        hex_str = ' '.join(f'{ord(c):02X}' for c in padded)
        chunks.append(padded)
        pad_note = f" (+{BLOCK_SIZE - len(raw)} '{PAD_CHAR}')" if len(raw) < BLOCK_SIZE else ""
        print(f"  Chunk {i+1}: {padded.encode().hex().upper()}  \"{padded}\"{pad_note}")

    # -----------------------------------------------------------------------
    # Step 6 – AES-128 Encryption  (ECB, chunk-by-chunk)
    # -----------------------------------------------------------------------
    plaintext_hex  = ''.join(c.encode().hex().upper() for c in chunks)
    ciphertext_raw = encrypt(message, aes_key)
    ciphertext_hex = ciphertext_raw.hex().upper()

    print(f"\n{SECTION}")
    print("  STEP 6 – AES-128 Encryption (ECB, chunk-by-chunk)")
    print(SECTION)
    print(f"  Plaintext  (hex): {plaintext_hex}")
    print(f"  Ciphertext (hex): {ciphertext_hex}")
    print(f"  Ciphertext size : {len(ciphertext_raw)} bytes\n")

    for i, chunk in enumerate(chunks):
        from Crypto.Cipher import AES as _AES
        _c = _AES.new(aes_key, _AES.MODE_ECB).encrypt(chunk.encode())
        print(f"  Block {i+1}: {_c.hex().upper()}")

    # -----------------------------------------------------------------------
    # Step 7 – Decryption by User B
    # -----------------------------------------------------------------------
    decrypted_msg = decrypt(ciphertext_raw, aes_key)

    print(f"\n{SECTION}")
    print("  STEP 7 – Decryption by User B")
    print(SECTION)
    print(f"  Decrypted message : \"{decrypted_msg}\"")
    if decrypted_msg == message:
        print("  ✓ Message integrity verified – matches original!")
    else:
        print("  ✗ ERROR: Decrypted message does NOT match original!")

    print(f"\n{DIVIDER}")
    print("  Simulation complete.")
    print(DIVIDER)


if __name__ == "__main__":
    main()
