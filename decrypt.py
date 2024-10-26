import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# AES decryption of files
def decrypt_file_aes(file_path, aes_key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)  # Read the first 16 bytes (IV)
        ciphertext = f.read()  # Read the rest (ciphertext)

    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    plaintext = cipher_aes.decrypt(ciphertext)

    # Save the decrypted file
    with open(file_path.replace('.enc', ''), 'wb') as f:
        f.write(plaintext)

# RSA decryption of the AES key
def decrypt_aes_key_rsa(encrypted_key, rsa_private_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)  # Decrypt AES key with RSA private key
    return aes_key

# Decrypt all files in the folder
def decrypt_folder(folder_path, rsa_private_key):
    # Load the encrypted AES key and IV from aes_key.bin
    with open(os.path.join(folder_path, 'aes_key.bin'), 'rb') as f:
        encrypted_aes_key = f.read(rsa_private_key.size_in_bytes())  # Size of RSA key
        aes_key = decrypt_aes_key_rsa(encrypted_aes_key, rsa_private_key)  # Decrypt AES key

    # Decrypt each file in the folder
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                decrypt_file_aes(file_path, aes_key)  # Decrypt file
                os.remove(file_path)  # Optional: Remove encrypted file after decryption

# RSA key loading
def load_rsa_keys():
    with open("private.pem", 'rb') as f:
        private_key = RSA.import_key(f.read())
    return private_key

# Main decryption process
if __name__ == "__main__":
    folder_to_decrypt = "C:\\Jason\\Computer Security"

    # Load RSA private key
    private_key = load_rsa_keys()

    # Decrypt the folder
    decrypt_folder(folder_to_decrypt, private_key)
