from rsa import newkeys, encrypt


def encrypt_rsa(text, exponent=65537, key_length=2048):
    # Generate an RSA key with the specified length and exponent
    """
    Encrypts a given text using RSA encryption.

    Parameters:
        text (str): The text to encrypt
        exponent (int): The exponent to use for the RSA key (default: 65537)
        key_length (int): The length of the RSA key in bits (default: 2048)

    Returns:
        tuple: A tuple containing the encrypted text and the public key
    """
    (public_key, private_key) = newkeys(key_length, exponent)

    # Encrypt the text using the public key
    encrypted_text = encrypt(text.encode(), public_key)

    return encrypted_text, public_key


# Example usage
text = "ESTAMOS EN CLASE DE CRIPTOGRAFIA"
encrypted_text, public_key = encrypt_rsa(text)

print("Encrypted text:", encrypted_text.hex())
print("Public key:", public_key.save_pkcs1().decode())
