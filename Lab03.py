import hashlib
import secrets


# Define P and G for DH Key-Exchange

P = int("2B1A1466A603FC6AF5AB96631", 16)

G = 2

# NOTICE for SecurePRNG(): To ensure Rollback Resistance, you must update the internal state using a hash 
# function after every generation block so that the process cannot be reversed.
class SecurePRNG():

    # Uses the DH shared secret to set the initial 32-byte state.
    def __init__(self, seed_int):
        seed_bytes = seed_int.to_bytes((seed_int.bit_length() + 7) // 8 or 1, "big")
        self.state = hashlib.sha256(b"SecurePRNG|seed|" + seed_bytes).digest()

    def reseed(self, extra_entropy):
        self.state = hashlib.sha256(b"SecurePRNG|reseed|" + self.state + extra_entropy).digest()

    # Produces n pseudorandom bytes.
    def generate(self, n):
        output = b""

        while len(output) < n:
            # 1. Generate keystream block from current state
            block = hashlib.sha256(b"SecurePRNG|block|" + self.state).digest()

            # 2. Immediately advance state (rollback resistance)
            self.state = hashlib.sha256(b"SecurePRNG|state|" + self.state).digest()

            output += block

        return output[:n]


class stream_cipher():
    # Logic: This function should call prng.generate() to get a keystream.
    # Operation: Return Plaintext XOR Keystream.
    pass


class Entity():
    # Initializes Alice/Bob with private/public keys.
    privateKey = b""
    publicKey = b""
    
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