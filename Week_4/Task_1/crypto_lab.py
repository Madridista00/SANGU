import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Step 1: Create original message.txt
original_message = b"""This is a secret message for the cryptography lab. It contains sensitive information that must be protected using both symmetric and asymmetric encryption techniques."""
with open('message.txt', 'wb') as f:
    f.write(original_message)
print("Created: message.txt")

# Step 2: Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Save private key 
with open('private.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  
    ))

# Save public key (PEM format)
with open('public.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
print("Created: public.pem, private.pem")

# Step 3: RSA Encryption
with open('message.txt', 'rb') as f:
    message = f.read()

# RSA encrypts in blocks; 
rsa_encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
with open('message_rsa_encrypted.bin', 'wb') as f:
    f.write(rsa_encrypted)
print("Created: message_rsa_encrypted.bin")

# Step 4: RSA Decryption
rsa_decrypted = private_key.decrypt(
    rsa_encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
with open('message_rsa_decrypted.txt', 'wb') as f:
    f.write(rsa_decrypted)
print("Created: message_rsa_decrypted.txt")

# Step 5: AES-256 Encryption
# Generate random 32-byte key (AES-256) and 16-byte IV
aes_key = os.urandom(32)
aes_iv = os.urandom(16)

# Save key and IV as binary files
with open('aes_key.bin', 'wb') as f:
    f.write(aes_key)
with open('aes_iv.bin', 'wb') as f:
    f.write(aes_iv)
print("Created: aes_key.bin, aes_iv.bin")

# Encrypt with AES-256-CBC
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
encryptor = cipher.encryptor()
# Pad message to block size
padded_message = message + b'\x00' * (16 - len(message) % 16)  
aes_encrypted = encryptor.update(padded_message) + encryptor.finalize()
with open('message_aes_encrypted.bin', 'wb') as f:
    f.write(aes_encrypted)
print("Created: message_aes_encrypted.bin")

# Step 6: AES Decryption
decryptor = cipher.decryptor()
aes_decrypted_padded = decryptor.update(aes_encrypted) + decryptor.finalize()
# Remove padding 
aes_decrypted = aes_decrypted_padded.rstrip(b'\x00')
with open('message_aes_decrypted.txt', 'wb') as f:
    f.write(aes_decrypted)
print("Created: message_aes_decrypted.txt")

# Verification
print("\nVerification:")
print("RSA Decrypted matches original:", rsa_decrypted == original_message)
print("AES Decrypted matches original:", aes_decrypted == original_message)

# Step 7: Generate explanation file
with open('rsa_vs_aes.txt', 'w') as f:
    f.write("""RSA vs AES Performance and Use-Case Differences

Performance:
- RSA (Asymmetric): Slower due to large key sizes (e.g., 2048-bit) and complex math (modular exponentiation). Encryption/decryption times are higher, especially for large files—suitable only for small data (< few KB) to avoid performance bottlenecks.
- AES (Symmetric): Much faster with fixed small keys (e.g., 256-bit) and simple block cipher operations. Ideal for bulk data encryption; hardware acceleration (e.g., AES-NI) makes it efficient even on large files.

Use Cases:
- RSA: Key exchange, digital signatures, or encrypting small secrets (e.g., session keys). Not for direct file encryption of large data due to speed and block size limits.
- AES: Bulk file/stream encryption, disk encryption (e.g., BitLocker), secure communications (e.g., TLS data transfer). Often combined with RSA (hybrid crypto) for secure key distribution.

In this lab: RSA was used directly for the file (small size), but in practice, we'd use RSA to encrypt an AES key, then AES for the file—balancing security and speed.
""")
print("Created: rsa_vs_aes.txt")
print("\nAll files generated! And Uploaded to GitHub. ")