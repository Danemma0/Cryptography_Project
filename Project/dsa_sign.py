from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
import os
import time

x = 11

while x > 0:
    private_key = dsa.generate_private_key(
        key_size=1024
    )
    public_key = private_key.public_key()

    message = os.urandom(50)

    #Time before digital signature
    before = time.perf_counter()

    # We can sign the message using "hash-then-sign".
    signature = private_key.sign(
        message,
        hashes.SHA256()
    )

    #Time after digital signature
    after = time.perf_counter()

    #Message to avoid first output to user
    if x == 11:
       print("Avoid first output as it may be a wrong reading!")

    #Printing Time
    print(f"{after - before:0.4f} seconds")
    x-=1