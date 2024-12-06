from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import os
import time

x = 11

while x > 0:
    #Time before keypair generation
    before = time.perf_counter()

    private_key = ec.generate_private_key(
        ec.SECP192R1()
    )

    public_key = private_key.public_key()

    #Time after keypair generation
    after = time.perf_counter()

    #Message to avoid first output to user
    if x == 11:
        print("Avoid first output as it may be a wrong reading!")

    #Printing Time
    print(f"{after - before:0.4f} seconds")
    x-=1