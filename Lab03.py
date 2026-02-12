import random


# NOTICE for SecurePRNG(): To ensure Rollback Resistance, you must update the internal state using a hash 
# function after every generation block so that the process cannot be reversed.
class SecurePRNG():
    # Uses the DH shared secret to set the initial 32-byte state.
    def __init__(self):
        pass

    # Produces n pseudorandom bytes.
    def generate(n):
        pass


class stream_cipher():
    # Logic: This function should call prng.generate() to get a keystream.
    # Operation: Return Plaintext XOR Keystream.
    pass


class Entity():
    # Initializes Alice/Bob with private/public keys.
    privateKey = ""
    publicKey = ""
    
    def __init__(self):
        pass

    # Returns public key as hex.
    def get_public_hex():
        pass

    # Calculates secret and initializes SecurePRNG().
    def establish_session():
        pass


class Network():
    #Initializes the network and stores a value for Mallory. 
    # Use this to “plug” Mallory into the network for the MITM demonstration
    def __init__(self):
        pass

    # Handles the transmission of data from the sender to the recipient. 
    # If Mallory is “plugged in”, she will intercept the traffic to perform the MITM attack.
    def send():
        pass


class Mallory():
    # Initializes Mallory with private/public keys.
    def __init__(self):
        pass

    # If Key Exchange: Store sender's key, generate fake secret, return Mallory's public key.
    # If Encrypted Message: Decrypt using "Sender-side" PRNG, modify string, Re-encrypt using "Recipient-side" PRNG.
    def intercept():
        pass


# Main Function
if __name__ == "__main__":
    Alice = Entity()
    Bob = Entity()