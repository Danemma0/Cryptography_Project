from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
import os
import time


def time_rsa_keypair_generation(bits):
    x = 10
    total_time = 0
    while x > 0:
        # Time before keypair generation
        before = time.perf_counter()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )
        public_key = private_key.public_key()

        # Time after keypair generation
        after = time.perf_counter()
        
        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_rsa_encryption(bits):
    x = 10
    total_time = 0
    while x > 0:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )

        public_key = private_key.public_key()

        def split_message(message, chunk_size):
            return [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

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

        # Storing message
        long_plaintext = os.urandom(10 * 1024)

        # Time before encrypting with chunking
        before = time.perf_counter()

        # We can encrypt large messages using chunking.
        long_ciphertext = encrypt_message(public_key, long_plaintext, 32)

        # Time after encrypting with chunking
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_rsa_decryption(bits):
    x = 10
    total_time = 0
    while x > 0:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )

        public_key = private_key.public_key()

        def split_message(message, chunk_size):
            return [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

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

        def decrypt_message(private_key, encrypted_chunks):
            decrypted_chunks = []
            for chunk in encrypted_chunks:
                decrypted_chunks.append(private_key.decrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ))
            return b"".join(decrypted_chunks)

        # Storing message into a variable
        long_plaintext = os.urandom(10 * 1024)

        # We can encrypt large messages using chunking.
        long_ciphertext = encrypt_message(public_key, long_plaintext, 32)

        # Time before decrypting with chunking
        before = time.perf_counter()

        # We can decrypt large messages using chunking.
        long_plaintext_2 = decrypt_message(private_key, long_ciphertext)

        # Time after decrypting with chunking
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_rsa_signing(bits):
    x = 10
    total_time = 0
    while x > 0:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )

        public_key = private_key.public_key()

        message = os.urandom(1024)

        # Time before digital signature
        before = time.perf_counter()

        # We can sign the message using "hash-then-sign".
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Time after digital signature
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_rsa_verification(bits):
    x = 10
    total_time = 0
    while x > 0:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )

        public_key = private_key.public_key()

        message = os.urandom(1024)

        # We can sign the message using "hash-then-sign".
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Time before signature verification
        before = time.perf_counter()

        # We can verify the signature.
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Time after signature verification
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_dsa_keypair_generation(bits):
    x = 10
    total_time = 0
    while x > 0:
        # Time before keypair generation
        before = time.perf_counter()

        private_key = dsa.generate_private_key(
            key_size=bits
        )
        public_key = private_key.public_key()

        # Time after keypair generation
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_dsa_signing(bits):
    x = 10
    total_time = 0
    while x > 0:
        private_key = dsa.generate_private_key(
            key_size=bits
        )
        public_key = private_key.public_key()

        message = os.urandom(50)

        # Time before digital signature
        before = time.perf_counter()

        # We can sign the message using "hash-then-sign".
        signature = private_key.sign(
            message,
            hashes.SHA256()
        )

        # Time after digital signature
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_dsa_verification(bits):
    x = 10
    total_time = 0
    while x > 0:
        private_key = dsa.generate_private_key(
            key_size=bits
        )
        public_key = private_key.public_key()

        message = os.urandom(50)

        # We can sign the message using "hash-then-sign".
        signature = private_key.sign(
            message,
            hashes.SHA256()
        )

        # Time before signature verification
        before = time.perf_counter()

        # We can verify the signature.
        public_key.verify(
            signature,
            message,
            hashes.SHA256()
        )

        # Time after signature verification
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_ecc_keypair_generation(curve):
    x = 10
    total_time = 0
    while x > 0:
        # Time before keypair generation
        before = time.perf_counter()

        private_key = ec.generate_private_key(
            curve
        )
        public_key = private_key.public_key()

        # Time after keypair generation
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_ecc_signing(curve):
    x = 10
    total_time = 0
    while x > 0:
        private_key = ec.generate_private_key(
            curve
        )
        public_key = private_key.public_key()

        message = os.urandom(50)

        # Time before digital signature
        before = time.perf_counter()

        # We can sign the message using "hash-then-sign".
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        # Time after digital signature
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time


def time_ecc_verification(curve):
    x = 10
    total_time = 0
    while x > 0:
        private_key = ec.generate_private_key(
            curve
        )
        public_key = private_key.public_key()

        message = os.urandom(50)

        # We can sign the message using "hash-then-sign".
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        # Time before signature verification
        before = time.perf_counter()

        # We can verify the signature.
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )

        # Time after signature verification
        after = time.perf_counter()

        total_time += (after - before)

        x -= 1
    return total_time / 10  # Return average time

# Define bit sizes for RSA and DSA, and the elliptic curve for ECC
rsa_sizes = [1024, 2048, 3072, 7680, 15360]  # Common RSA bit sizes
dsa_sizes = [1024, 2048, 3072, 4096]  # Common DSA bit sizes
ecc_curves = [ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]  # ECC curve types

# Run RSA operations
for rsa_size in rsa_sizes:
    print(f"\nRunning RSA {rsa_size}-bit operations:")
    print(f"RSA {rsa_size}-bit key pair generation time: {time_rsa_keypair_generation(rsa_size):0.4f} seconds")
    print(f"RSA {rsa_size}-bit encryption time: {time_rsa_encryption(rsa_size):0.4f} seconds")
    print(f"RSA {rsa_size}-bit decryption time: {time_rsa_decryption(rsa_size):0.4f} seconds")
    print(f"RSA {rsa_size}-bit signing time: {time_rsa_signing(rsa_size):0.4f} seconds")
    print(f"RSA {rsa_size}-bit verification time: {time_rsa_verification(rsa_size):0.4f} seconds")

# Run DSA operations
for dsa_size in dsa_sizes:
    print(f"\nRunning DSA {dsa_size}-bit operations:")
    print(f"DSA {dsa_size}-bit key pair generation time: {time_dsa_keypair_generation(dsa_size):0.4f} seconds")
    print(f"DSA {dsa_size}-bit signing time: {time_dsa_signing(dsa_size):0.4f} seconds")
    print(f"DSA {dsa_size}-bit verification time: {time_dsa_verification(dsa_size):0.4f} seconds")

# Run ECC operations
for curve in ecc_curves:
    curve_name = curve.name  # Get the curve name for printing
    print(f"\nRunning ECC with {curve_name} curve:")
    print(f"ECC key pair generation time: {time_ecc_keypair_generation(curve):0.4f} seconds")
    print(f"ECC signing time: {time_ecc_signing(curve):0.4f} seconds")
    print(f"ECC verification time: {time_ecc_verification(curve):0.4f} seconds")
