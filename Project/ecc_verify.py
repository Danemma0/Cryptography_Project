from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import os
import time

x = 11

while x > 0:
    private_key = ec.generate_private_key(
        ec.SECP192R1()
    )

    public_key = private_key.public_key()

    message = os.urandom(50)

    # We can sign the message using "hash-then-sign".
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    #Time before signature verification
    before = time.perf_counter()

    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )

    #Time after signature verification
    after = time.perf_counter()

    #Message to avoid first output to user
    if x == 11:
        print("Avoid first output as it may be a wrong reading!")

    #Printing Time
    print(f"{after - before:0.4f} seconds")
    x-=1
    
