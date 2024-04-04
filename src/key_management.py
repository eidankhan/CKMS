import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Define the directory name for saving keys
keys_directory = 'keys'

# Create the directory if it does not exist
if not os.path.exists(keys_directory):
    os.makedirs(keys_directory)


def generate_symmetric_key(key_size=256):
    """
    Generate a symmetric key for AES encryption.

    Args:
    key_size (int): The size of the key in bits. Must be one of 128, 192, or 256.

    Returns:
    bytes: The generated symmetric key.
    """
    if key_size not in [128, 192, 256]:
        raise ValueError("Key size must be 128, 192, or 256 bits.")
    return os.urandom(key_size // 8)


def generate_private_key(key_size=2048):
    """
    Generate a private key for asymmetric encryption using RSA.

    Args:
    key_size (int): The number of bits long the key should be.

    Returns:
    rsa.RSAPrivateKey: The generated private RSA key.
    """
    return rsa.generate_private_key(
        public_exponent=65537,  # used in the encryption process and value "65537" is a commonly used prime number
        # for the public exponent because it's considered to be a good compromise between security and performance.
        key_size=key_size,
        backend=default_backend()
    )


from cryptography.hazmat.primitives import serialization


def serialize_private_key(private_key, password=None):
    """
    Serialize the private key to PEM format.

    Args:
    private_key (rsa.RSAPrivateKey): The private RSA key to serialize.
    password (bytes, optional): A password to encrypt the key.

    Returns:
    bytes: The PEM-encoded private key.
    """
    # Check if a password was provided for encrypting the private key.
    if password is not None:
        # If a password is provided, use it to encrypt the private key using the best available encryption algorithm
        # provided by the library.
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        # If no password is provided, the private key will be serialized without encryption.
        encryption_algorithm = serialization.NoEncryption()

    # Serialize the private key to PEM format using the specified encryption algorithm.
    # PEM (Privacy-Enhanced Mail) is a base64 encoded format with header and footer lines.
    # It is a standard format for storing and transmitting cryptographic keys and certificates.
    return private_key.private_bytes(
        # Specify the encoding for the serialized output. PEM is the most common encoding format for sharing keys.
        encoding=serialization.Encoding.PEM,
        # Specify the format for the private key. PKCS8 is a standard syntax for storing private key information.
        format=serialization.PrivateFormat.PKCS8,
        # Apply the chosen encryption algorithm (either encrypted with a password or not encrypted).
        encryption_algorithm=encryption_algorithm
    )


def generate_public_key(private_key):
    """
    Generate the public key from a private key.

    Args:
    private_key (rsa.RSAPrivateKey): The private RSA key.

    Returns:
    rsa.RSAPublicKey: The generated public RSA key.
    """
    return private_key.public_key()


def serialize_public_key(public_key):
    """
    Serialize the public key to PEM format.

    Args:
    public_key (rsa.RSAPublicKey): The public RSA key to serialize.

    Returns:
    bytes: The PEM-encoded public key.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def save_key_to_file(key, filename):
    """
    Save a key to a file in the 'keys' directory.

    Args:
    key (bytes): The key to save.
    filename (str): The name of the file to save the key to.
    """
    file_path = os.path.join(keys_directory, filename)
    with open(file_path, 'wb') as key_file:
        key_file.write(key)


# Generate a symmetric key
symmetric_key = generate_symmetric_key()

# Generate a private key and serialize it
private_key = generate_private_key()
pem_private_key = serialize_private_key(private_key)

# Generate a public key from the private key and serialize it
public_key = generate_public_key(private_key)
pem_public_key = serialize_public_key(public_key)

# Output the keys to verify (in a real scenario, you wouldn't print your keys)
# print(f"Symmetric key: {symmetric_key}")
# print(f"Private key: {pem_private_key.decode('utf-8')}")
# print(f"Public key: {pem_public_key.decode('utf-8')}")

# Save keys to local directory
save_key_to_file(pem_private_key, 'private_key.pem')
save_key_to_file(pem_public_key, 'public_key.pem')

print(f"Keys are successfully saved in the '{keys_directory}' directory.")
