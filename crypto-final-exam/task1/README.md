## Encryption Flow (Step-by-Step)

| Step | Actor  | Action                                                                                   | Tool Used           |
|------|--------|------------------------------------------------------------------------------------------|---------------------|
| 1    | User A | Generates a 2048-bit RSA key pair (private + public)                                     | Python `cryptography` |
| 2    | User A | Shares the **public key** with User B (in real life: via secure channel or key server)   | —                   |
| 3    | User B | Generates a random 256-bit AES key and a random 128-bit IV                               | `os.urandom()`      |
| 4    | User B | Encrypts the secret message with **AES-256-CBC** using the random key and IV             | `Cipher(AES, CBC)`  |
| 5    | User B | Encrypts the AES key itself with **RSA-2048 + OAEP-SHA256** using User A’s public key    | `public_key.encrypt()` |
| 6    | User B | Sends two files to User A: <br>• `encrypted_message.bin` (IV || ciphertext) <br>• `aes_key_encrypted.bin` | —                   |
| 7    | User A | Decrypts the AES key using his **RSA private key** + OAEP padding                        | `private_key.decrypt()` |
| 8    | User A | Decrypts the message using the recovered AES key and the IV from the file                 | `Cipher(AES, CBC)`  |
| 9    | User A | Recovers the original plaintext message                                                   | —                   |

## Generated Files (all present)
- `message.txt` → original plaintext  
- `encrypted_message.bin` → IV (16 bytes) + AES-256-CBC ciphertext  
- `aes_key_encrypted.bin` → RSA-encrypted AES key (256 bytes)  
- `decrypted_message.txt` → recovered plaintext (identical to original)

## Why Hybrid Encryption?
- RSA is slow → only used for the small AES key (32 bytes)  
- AES is very fast → used for the actual message (any size)  
→ Best of both worlds: **strong security + excellent performance**

**Result:** Only User A (with the private key) can read the message. Perfect forward secrecy not required for this prototype.
