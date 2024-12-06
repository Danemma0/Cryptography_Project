from cryptography.hazmat.primitives.asymmetric import rsa
import time

x = 11

while x > 0:
    #Time before keypair generation
    before = time.perf_counter()

    #Generating keypair
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024
    )
    public_key = private_key.public_key()

    #Time after keypair generation
    after = time.perf_counter()

    #Message to avoid first output to user
    if x == 11:
        print("Avoid first output as it may be a wrong reading!")

    #Printing time
    print(f"{after - before:0.4f} seconds")
    x -= 1