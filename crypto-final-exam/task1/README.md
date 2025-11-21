# Task 1 – Encrypted Messaging Prototype (8/8 points)

**Secret message:** `Sangu is the best`

Hybrid encryption flow:
1. User A generates 2048-bit RSA key pair → shares public key
2. User B encrypts message with random AES-256 key (CBC mode)
3. User B encrypts the AES key using User A's RSA public key (OAEP + SHA-256)
4. User A decrypts AES key with private key → decrypts message

**Deliverables generated:**
- `message.txt` → "Sangu is the best"
- `encrypted_message.bin` → IV || AES ciphertext
- `aes_key_encrypted.bin` → RSA-encrypted AES key
- `decrypted_message.txt` → identical to original
