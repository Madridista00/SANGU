#Task_1

def caesar_decrypt(ciphertext, shift):
    """
    Decrypt a Caesar cipher text with a given shift.
    Handles both uppercase and lowercase letters, preserves non-alphabetic characters.
    """
    result = ""
    for char in ciphertext:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97  # A=65, a=97
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# Lab ciphertext
text = "Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu."

# Brute-force: Try all shifts
print("Brute-force Caesar decryption results:")
for i in range(26):
    decrypted = caesar_decrypt(text, i)
    print(f"Shift {i}: {decrypted}")

# Direct decryption with known shift (14)
print(f"\nDecrypted with shift 14: {caesar_decrypt(text, 14)}")

'''
Discussion: Why is Caesar Cipher Insecure? Where Might Legacy Systems Still Use Similar Encryption?

Insecurity Reasons:

Limited Key Space: There are only 25 possible shifts (excluding shift 0), making brute-force attacks trivial—even manually. Modern computers can test all in milliseconds.
Vulnerable to Frequency Analysis: English letter frequencies (e.g., 'E' ~12.7%, 'T' ~9%) don't change under shifting. 
No diffusion or confusion properties (as in modern ciphers like AES).
No Integrity/Authentication: Easy to detect tampering or guess plaintext.


Legacy System Usage:

Obfuscation in Configs/Scripts: Old Unix rot13 utilities (a Caesar variant with shift 13) for hiding spoilers or simple data masking in emails/scripts.
Early Telecom/Embedded Systems: Legacy routers, SCADA systems, or IoT devices from the 1980s-90s might use it for basic PIN protection or command encoding due to low compute needs.
Educational/Non-Critical Tools: Still appears in puzzles, basic password hashing (e.g., old games), or as a first layer in multi-stage encryption in outdated software like early PGP variants.
'''


#Task_2
import base64

def caesar_decrypt(ciphertext, shift):
    """
    Decrypt a Caesar cipher text with a given shift.
    Handles mixed case: uppercase stays uppercase, lowercase stays lowercase.
    Preserves non-alphabetic characters.
    """
    result = ""
    for char in ciphertext:
        if char.isalpha():
            if char.isupper():
                ascii_offset = 65  
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            else:  
                ascii_offset = 97  
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# Caesar Brute-Force
ct_caesar = "mznxpz"
print("Step 1: Caesar Brute-Force Results:")
for i in range(26):
    dec = caesar_decrypt(ct_caesar, i)
    print(f"Shift {i}: {dec}")
# Shift 21 -> "rescue"

# Step 2: Anagram 
passphrase = "secure"
print(f"\nStep 2: Passphrase: {passphrase}")

# Step 3: XOR Decryption
ct_b64 = "Jw0KBlIMAEUXHRdFKyoxVRENEgkPEBwCFkQ="
ct = base64.b64decode(ct_b64)
key = passphrase.encode('utf-8')
pt = bytearray()
for i in range(len(ct)):
    pt.append(ct[i] ^ key[i % len(key)])
decrypted = pt.decode('utf-8')
print(f"Step 3: Decrypted Message: {decrypted}")