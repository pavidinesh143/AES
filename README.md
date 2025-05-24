# EX-8-ADVANCED-ENCRYPTION-STANDARD ALGORITHM


# PAVITHRA S

# 212223220072

# Aim:
To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

# ALGORITHM:
AES is based on a design principle known as a substitution–permutation.
AES does not use a Feistel network like DES, it uses variant of Rijndael.
It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
AES operates on a 4 × 4 column-major order array of bytes, termed the state
# PROGRAM:
def xor_encrypt_decrypt(input_text, key):
    key_length = len(key)
    result = []

    for i in range(len(input_text)):
        xor_char = chr(ord(input_text[i]) ^ ord(key[i % key_length]))
        result.append(xor_char)

    return ''.join(result)

def main():
    url = "WELCOME"
    key = "secretkey"

    print(f"Original text: {url}")

    # Encrypt
    encrypted = xor_encrypt_decrypt(url, key)
    print(f"Encrypted text: {''.join(f'{ord(c):02X}' for c in encrypted)}")  # Hex format

    # Decrypt
    decrypted = xor_encrypt_decrypt(encrypted, key)
    print(f"Decrypted text: {decrypted}")

if __name__ == "__main__":
    main()

# OUTPUT:
![441515204-62e2eb89-3727-4dd8-88fd-9e109fe94f96](https://github.com/user-attachments/assets/ddebccdc-d570-4229-a038-1465635571a0)
# RESULT:
The expriment is successfully Executed.

