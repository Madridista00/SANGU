Alice wants to send Bob a secret file securely using **hybrid encryption**.

## Step-by-Step Encryption & Decryption Flow

| Step | Actor  | Action                                                                                   | Output File                     |
|------|--------|------------------------------------------------------------------------------------------|---------------------------------|
| 1    | Bob    | Generates 2048-bit RSA key pair                                                          | `public.pem`, `private.pem`     |
| 2    | Alice  | Creates plaintext message                                                                | `alice_message.txt`             |
| 3    | Alice  | Generates random 256-bit AES key + 128-bit IV                                            | (in memory)                     |
| 4    | Alice  | Encrypts the file with **AES-256-CBC** using the random key + IV                          | `encrypted_file.bin`            |
| 5    | Alice  | Encrypts the AES key with **Bob’s RSA public key** (OAEP + SHA-256 padding)              | `aes_key_encrypted.bin`         |
| 6    | Alice  | Sends three files to Bob: encrypted file + encrypted AES key + (IV is inside encrypted_file.bin) | —                               |
| 7    | Bob    | Decrypts the AES key using his **RSA private key**                                       | (in memory)                     |
| 8    | Bob    | Extracts IV from first 16 bytes of `encrypted_file.bin`                                  | (in memory)                     |
| 9    | Bob    | Decrypts the file using recovered AES key + IV                                           | `decrypted_message.txt`         |
| 10   | Bob    | Computes SHA-256 of original and decrypted file → **integrity verified**                 | Console: "PASS"                 |

**All required files are present and identical after decryption.**

## AES vs RSA Comparison (2025)

| Criteria         | AES-256                                | RSA-2048                                      |
|------------------|----------------------------------------|-----------------------------------------------|
| **Type**         | Symmetric (shared secret)              | Asymmetric (public/private key pair)          |
| **Speed**        | Extremely fast (~300–800 MB/s on modern CPU) | Very slow (~0.1–1 MB/s) – only for small data |
| **Typical use case** | Bulk data / file encryption (any size) | Key exchange, digital signatures, small data  |
| **Key size**     | 256 bits                               | 2048–4096 bits                                |
| **Security status (2025)** | No practical attack (quantum-resistant in Grovers → still safe) | Safe against classical computers<br>Weak against future large quantum computers (Shor’s algorithm) |
| **Best for**     | Encrypting the actual message/file     | Securely transporting the AES key             |

### Why Hybrid (RSA + AES) is the gold standard
- RSA alone would be too slow for large files  
- AES alone has no secure key distribution mechanism  
→ **Hybrid = perfect security + excellent performance** (used in HTTPS, PGP, Signal, HTTPS, SSH, etc.)

**Integrity verification result:** SHA-256 hashes match → **PASS**
