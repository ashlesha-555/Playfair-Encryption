pip install cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes  
import base64
import os
import string

def generate_secure_key(keyword):
    salt = os.urandom(16)  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(keyword.encode()))
    return key, salt

def base64_encode(data):
    return base64.urlsafe_b64encode(data.encode()).decode()

def base64_decode(encoded_data):
    return base64.urlsafe_b64decode(encoded_data.encode()).decode()

def generate_playfair_matrix(keyword):
    keyword = ''.join(dict.fromkeys(keyword.upper()))  # Remove duplicates
    alphabet = string.ascii_uppercase.replace('J', '')  # Playfair uses I/J as one letter
    matrix = []

    for char in keyword + alphabet:
        if char not in matrix:
            matrix.append(char)

    matrix = [matrix[i:i+5] for i in range(0, 25, 5)]
    return matrix

def find_position(matrix, letter):
    for i, row in enumerate(matrix):
        if letter in row:
            return i, row.index(letter)
    return None

def encrypt_playfair(plaintext, matrix):
    plaintext = plaintext.upper().replace('J', 'I')
    plaintext = ''.join([char for char in plaintext if char in string.ascii_uppercase])

    encrypted_text = []
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        if i + 1 < len(plaintext):
            b = plaintext[i + 1]
        else:
            b = 'X'

        if a == b:
            b = 'X'

        encrypted_text.append(a + b)
        i += 2 if a != b else 1

    ciphertext = ''
    for pair in encrypted_text:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])

        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]

    return ciphertext

def decrypt_playfair(ciphertext, matrix):
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5]
            plaintext += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1]
            plaintext += matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2]
            plaintext += matrix[row2][col1]

    return plaintext

keyword = "monarchy"
matrix = generate_playfair_matrix(keyword)

secure_key, salt = generate_secure_key(keyword)
print(f"Secure key: {secure_key}")
print(f"Salt: {salt}")

plaintext = "hello"
ciphertext = encrypt_playfair(plaintext, matrix)
decrypted_text = decrypt_playfair(ciphertext, matrix)

encoded_ciphertext = base64_encode(ciphertext)
encoded_salt = base64_encode(salt.decode('latin-1'))  # Encode salt for secure storage

print(f"Keyword: {keyword}")
print("Playfair Matrix:")
for row in matrix:
    print(' '.join(row))

print(f"\nPlaintext: {plaintext}")
print(f"Ciphertext: {ciphertext}")  
print(f"Decrypted Text: {decrypted_text}")
