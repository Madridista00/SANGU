from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Bob generates RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

with open("task2/public.pem", "wb") as f:
    f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo))
with open("task2/private.pem", "wb") as f:
    f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PrivateFormat.PKCS8,
                                      encryption_algorithm=serialization.NoEncryption()))

# Alice creates original file
with open("task2/alice_message.txt", "w") as f:
    f.write("Sangu really is the best! This message must remain confidential.\n")

plaintext = open("task2/alice_message.txt", "rb").read()
aes_key = os.urandom(32)
iv = os.urandom(16)

# Alice encrypts file
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
padded = plaintext + b"\x00" * (16 - len(plaintext) % 16)
ct = encryptor.update(padded) + encryptor.finalize()

with open("task2/encrypted_file.bin", "wb") as f:
    f.write(iv + ct)

enc_key = public_key.encrypt(aes_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
with open("task2/aes_key_encrypted.bin", "wb") as f:
    f.write(enc_key)

# Bob decrypts
dec_key = private_key.decrypt(enc_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

cipher = Cipher(algorithms.AES(dec_key), modes.CBC(iv))
decryptor = cipher.decryptor()
pt = decryptor.update(ct) + decryptor.finalize().rstrip(b"\x00")

with open("task2/decrypted_message.txt", "wb") as f:
    f.write(pt)

# Integrity check
orig_h = hashes.Hash(hashes.SHA256()); orig_h.update(plaintext)
dec_h  = hashes.Hash(hashes.SHA256()); dec_h.update(pt)
print("Task 2 integrity:", "PASS" if orig_h.finalize() == dec_h.finalize() else "FAIL")
