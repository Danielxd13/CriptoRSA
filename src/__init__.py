import rsa
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
    (public_key, private_key) = rsa.newkeys(key_length, exponent)

    # Encrypt the text using the public key and private key
    encrypted_text = rsa.encrypt(text.encode(), public_key)
    
    return encrypted_text, public_key, private_key

def sign_message(message, private_key):
    # convertir la clave privada a formato PEM
    private_key_pem = private_key.save_pkcs1()      

    # cargar la clave privada en formato PEM
    private_key_loaded = rsa.PrivateKey.load_pkcs1(private_key_pem) 

    return rsa.pkcs1.sign(message.encode(), private_key_loaded, 'SHA-256')

# Example usage
text = "ESTAMOS EN CLASE DE CRIPTOGRAFIA"
encrypted_text, public_key, private_key = encrypt_rsa(text)

print("Encrypted text hex: \n", encrypted_text.hex())
print("Public key: \n", public_key.save_pkcs1().decode())

# Sign the message
signature = sign_message(text, private_key)
print("Firma con RSA: \n", signature)