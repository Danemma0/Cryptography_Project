from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os 
import time

x = 11

while x > 0:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )

    public_key = private_key.public_key()

    def split_message(message, chunk_size):
        return [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]

    def encrypt_message(public_key, message, chunk_size):
        encrypted_chunks = []
        for chunk in split_message(message, chunk_size):
            encrypted_chunks.append(public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ))
        return encrypted_chunks

    #Storing message
    long_plaintext = os.urandom(10 * 1024)

    #Time before encrypting with chunking
    before = time.perf_counter()

    # We can encrypt large messages using chunking.
    long_ciphertext = encrypt_message(public_key, long_plaintext, 32)

    #Time after encrypting with chunking
    after = time.perf_counter()

    #Message to avoid first output to user
    if x == 11:
        print("Avoid first output as it may be a wrong reading!")
    #Printing time
    print(f"{after - before:0.4f} seconds")
    x-=1