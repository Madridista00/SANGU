from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size is 16 bytes
KEY = b"this_is_16_bytes"

# Ciphertext = IV + encrypted blocks
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

# ------------------------------------------------------------
# Padding Oracle
# ------------------------------------------------------------
def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid PKCS#7 padding."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]

        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()

        return True
    except Exception:
        return False


# ------------------------------------------------------------
# Task 2: Split blocks
# ------------------------------------------------------------
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into equal-sized blocks."""
    if len(data) % block_size != 0:
        raise ValueError("Data length is not a multiple of block size")
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


# ------------------------------------------------------------
# Task 3: Decrypt single block using padding oracle attack
# ------------------------------------------------------------
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Decrypt a single AES-CBC-encrypted block with a padding oracle."""
    recovered_intermediate = bytearray(BLOCK_SIZE)
    modified = bytearray(prev_block)

    for pad in range(1, BLOCK_SIZE + 1):

        # fix all known bytes to enforce required padding
        for j in range(1, pad):
            modified[-j] = recovered_intermediate[-j] ^ pad

        found = False
        for guess in range(256):
            modified[-pad] = guess
            test_ct = bytes(modified) + target_block
            if padding_oracle(test_ct):
                recovered_intermediate[-pad] = guess ^ pad
                found = True
                break

        if not found:
            raise Exception(f"Failed to recover byte for pad={pad}")

    # P = I XOR C_prev
    plaintext_block = bytes(
        recovered_intermediate[i] ^ prev_block[i]
        for i in range(BLOCK_SIZE)
    )
    return plaintext_block


# ------------------------------------------------------------
# Task 4: Full padding oracle attack
# ------------------------------------------------------------
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    plaintext = bytearray()

    print(f"[*] Total blocks (including IV): {len(blocks)}")

    for i in range(1, len(blocks)):
        print(f"[*] Decrypting block {i}/{len(blocks)-1} ...")
        pt_block = decrypt_block(blocks[i-1], blocks[i])
        plaintext.extend(pt_block)

    return bytes(plaintext)


# ------------------------------------------------------------
# Task 5: Remove PKCS#7 padding and decode
# ------------------------------------------------------------
def unpad_and_decode(plaintext: bytes) -> str:
    try:
        unpadder = padding.PKCS7(128).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
    except Exception:
        return f"[Unpad failed] Hex: {plaintext.hex()}"

    try:
        return unpadded.decode("utf-8")
    except UnicodeDecodeError:
        return f"[Not UTF-8] Hex: {unpadded.hex()}"


# ------------------------------------------------------------
# Main Execution
# ------------------------------------------------------------
if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)

        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f"Raw bytes:   {recovered}")
        print(f"Hex output:  {recovered.hex()}")

        decoded = unpad_and_decode(recovered)
        print("\nFinal plaintext:")
        print(decoded)

    except Exception as e:
        print(f"\nError: {e}")
