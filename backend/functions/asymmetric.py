from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256

def encrypt_asymmetric(public_key, data):
    if isinstance(public_key, tuple):
        public_key = public_key[0]
        if isinstance(public_key, bytearray):
            public_key = bytes(public_key)
        public_key = serialization.load_pem_public_key(public_key, backend=None)
    if isinstance(data, tuple):
        data = data[0]
    if isinstance(data, bytearray):
        data = bytes(data)

    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt_asymmetric(private_key, encrypted_data):
    if isinstance(private_key, tuple):
        private_key = private_key[0]
        if isinstance(private_key, bytearray):
            private_key = bytes(private_key)
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=None)
    if isinstance(encrypted_data, tuple):
        encrypted_data = encrypted_data[0]
    if isinstance(encrypted_data, bytearray):
        encrypted_data = bytes(encrypted_data)

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return decrypted_data.decode('utf-8')
