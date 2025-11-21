from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# User A generates RSA key pair (and shares public key)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# User B sends this exact message
message = b"Sangu is the best"

# User B: generate random AES-256 key + IV
aes_key = os.urandom(32)
iv = os.urandom(16)

# Encrypt message with AES-256-CBC
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
padded = message + b"\x00" * (16 - len(message) % 16)
encrypted_msg = encryptor.update(padded) + encryptor.finalize()

# Save encrypted message: IV (16 bytes) + ciphertext
with open("task1/encrypted_message.bin", "wb") as f:
    f.write(iv + encrypted_msg)

# Encrypt AES key with User A's RSA public key
enc_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
with open("task1/aes_key_encrypted.bin", "wb") as f:
    f.write(enc_aes_key)

# User A decrypts
decrypted_aes_key = private_key.decrypt(
    enc_aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

with open("task1/encrypted_message.bin", "rb") as f:
    data = f.read()
    iv_rec = data[:16]
    ct = data[16:]

cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv_rec))
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ct) + decryptor.finalize()
decrypted = decrypted_padded.rstrip(b"\x00")

# Save all required files
with open("task1/message.txt", "wb") as f:
    f.write(message)
with open("task1/decrypted_message.txt", "wb") as f: f.write(decrypted)

print("Task 1 completed – message: 'Sangu is the best'")
