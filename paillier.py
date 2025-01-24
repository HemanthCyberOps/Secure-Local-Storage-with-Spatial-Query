from phe import paillier, EncryptedNumber  # Ensure EncryptedNumber is imported

# Key generation
public_key, private_key = paillier.generate_paillier_keypair()

def encrypt_data(data):
    """Encrypt numeric or serialized string data."""
    serialized_data = []
    for value in data:
        if isinstance(value, (int, float)):
            serialized_data.append(value)
        elif isinstance(value, str):
            serialized_data.append(hash(value) % (10**15))  # Serialize strings into numeric hashes
        else:
            raise ValueError("encrypt_data: Unsupported data type.")
    return [public_key.encrypt(value) for value in serialized_data]

def decrypt_data(encrypted_data):
    """Decrypt numeric data."""
    return [private_key.decrypt(value) for value in encrypted_data]
