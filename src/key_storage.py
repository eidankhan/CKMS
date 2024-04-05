import os
import json
from cryptography.fernet import Fernet
import datetime
import os

# Define the directory name for saving keys
encrypted_keys_directory = 'encrypted_keys'

# Create the directory if it does not exist
if not os.path.exists(encrypted_keys_directory):
    os.makedirs(encrypted_keys_directory)

# Function to generate a new encryption key for securing the cryptographic keys
def generate_encryption_key():
    return Fernet.generate_key()

# Function to initialize the Fernet cipher suite with the encryption key
def initialize_cipher(encryption_key):
    return Fernet(encryption_key)

# Function to encrypt a cryptographic key
def encrypt_key(cipher_suite, key_to_encrypt):
    return cipher_suite.encrypt(key_to_encrypt)

# Function to decrypt a cryptographic key
def decrypt_key(cipher_suite, encrypted_key):
    return cipher_suite.decrypt(encrypted_key)

# Function to securely store an encrypted key
def store_encrypted_key(encrypted_key, filename):
    file_path = os.path.join(encrypted_keys_directory, filename)
    with open(file_path, 'wb') as file_object:
        file_object.write(encrypted_key)

# Function to load an encrypted key from a file
def load_encrypted_key(filename):
    file_path = os.path.join(encrypted_keys_directory, filename)
    with open(file_path, 'rb') as file_object:
        return file_object.read()

# Function to create an audit log entry
def create_audit_log(action, key_name):
    # Create the log entry as a string
    log_entry = f"Action: {action}, Key Name: {key_name}, Timestamp: {str(datetime.datetime.now())}\n"

    # Append the log entry to the audit_log.txt file
    with open('audit_log.txt', 'a') as log_file:
        log_file.write(log_entry)

def read_key_from_pem(pem_filename):
    # Print the current working directory
    print(f"Current working directory: {os.getcwd()}")

    # Construct the full path to the PEM file
    pem_file_path = os.path.join("keys", pem_filename)
    pem_file_path = os.path.normpath(pem_file_path)

    # Print the file path being accessed
    print(f"Attempting to access file at: {pem_file_path}")

    # Check if the file exists

    if os.path.isfile(pem_file_path):
        print("File exists.")
        with open(pem_file_path, 'rb') as pem_file:
            return pem_file.read()
    else:
        print("File does not exist.")
        raise FileNotFoundError(f"The file {pem_file_path} does not exist.")

# Function to write an encrypted key to a PEM file
def write_encrypted_key_to_pem(encrypted_key, pem_filename):
    """
    Writes an encrypted key to a PEM file.
    """
    with open(pem_filename, 'wb') as pem_file:
        pem_file.write(encrypted_key)

# Function to save a key to a file
def save_key_to_file(key, filename):
    with open(filename, 'wb') as file_object:
        file_object.write(key)

# Function to read a key from a file
def read_key_from_file(filename):
    with open(filename, 'rb') as file_object:
        return file_object.read()

# Example usage
# Generate a new encryption key
encryption_key = generate_encryption_key()

# Initialize the cipher suite
cipher_suite = initialize_cipher(encryption_key)
# Read the private key from the PEM file

pem_file_name = "private_key.pem"
generated_key = read_key_from_pem(pem_file_name)

# Encrypt the generated key
encrypted_private_key = encrypt_key(cipher_suite, generated_key)

# Store the encrypted private key
store_encrypted_key(encrypted_private_key, 'encrypted_private_key.bin')

# Create an audit log entry for the private key encryption
create_audit_log('encrypt', 'private_key.pem')


# # To decrypt the key, load the encrypted key and use the cipher suite
# loaded_encrypted_key = load_encrypted_key('encrypted_private_key.bin')
# decrypted_key = decrypt_key(cipher_suite, loaded_encrypted_key)
#
# # Save the original key to a file
# save_key_to_file(generated_key, pem_file_name)
#
# # Verify the decrypted key is the same as the original
# assert decrypted_key == pem_file_name
# #
# # # Create an audit log entry for decryption
# # create_audit_log('decrypt', 'my_secret_key')
# #
# # # Note: In a real-world scenario, the encryption key should be stored securely
# # # and not in the same location as the encrypted keys.
