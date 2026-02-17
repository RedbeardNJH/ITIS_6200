import hashlib
import math
import secrets

# UI helpers
def print_header(text):
    print(f"\n{'='*60}\n{text}\n{'='*60}")
def print_step(text):
    print(f"\n>> {text}")
def print_info(label, value):
    print(f" [{label}]: {str(value)[:70]}...")

# Define P and G for DH Key-Exchange

P = int("2B1A1466A603FC6AF5AB96631", 16)
G = 2

# NOTICE for SecurePRNG(): To ensure Rollback Resistance, you must update the internal state using a hash 
# function after every generation block so that the process cannot be reversed.
class SecurePRNG():

    # Uses the DH shared secret to set the initial 32-byte state.
    def __init__(self, seed_int):
        byte_length = max(1, math.ceil(seed_int.bit_length() / 8))
        seed_bytes = seed_int.to_bytes(byte_length, "big")
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


def stream_cipher(a, b):
    # Logic: This function should call prng.generate() to get a keystream.
    # Operation: Return Plaintext XOR Keystream.
    return bytes(byte1 ^ byte2 for byte1, byte2 in zip(a, b))


class Entity():
    # Initializes Alice/Bob with private/public keys.
    
    def __init__(self, name):
        self.name = name
        self.privatekey = secrets.randbelow(P - 2) + 1
        self.publickey = pow(G, self.privatekey, P)
        self.PRNG = None

    # Returns public key as hex.
    def get_public_hex(self):
        return hex(self.publickey)

    # Calculates secret and initializes SecurePRNG().
    def establish_session(self, partner_public_hex):
        partner_pub = int(partner_public_hex, 16)
        shared_secret = pow(partner_pub, self.privatekey, P)
        self.PRNG = SecurePRNG(shared_secret)
        


class Network():
    #Initializes the network and stores a value for Mallory. 
    # Use this to “plug” Mallory into the network for the MITM demonstration
    def __init__(self):
        self.mallory = None

    # Handles the transmission of data from the sender to the recipient. 
    # If Mallory is “plugged in”, she will intercept the traffic to perform the MITM attack.
    def send(self, sender, recipient, payload):
        print(f"[NET] {sender} -> {recipient}: {str(payload)[:60]}...")
        if self.mallory:
            return self.mallory.intercept(sender, recipient, payload)
        return payload


class Mallory():
    # Initializes Mallory with private/public keys.
    def __init__(self):
        self.privatekey = None
        self.publichex = None
        self.alice_prng = None
        self.bob_prng = None

    # If Key Exchange: Store sender's key, generate fake secret, return Mallory's public key.
    # If Encrypted Message: Decrypt using "Sender-side" PRNG, modify string, Re-encrypt using "Recipient-side" PRNG.
    def intercept(self, sender, recipient, payload):
        pass

def main():
    # ==========================================
    # SCENARIO A: BENIGN (SECURE) COMMUNICATION
    # ==========================================
    print_header("SCENARIO A: BENIGN (SECURE) COMMUNICATION")

    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()

    # Step 0: Parameters
    print_step("Step 0: Global Group Parameters")
    print_info("G (Generator)", G)
    print_info("P (Prime)", P)

    # Step 1: Public Key Exchange
    print_step("Step 1: Public Key Exchange")
    print_info("Alice Private (a)", alice.privatekey)
    print_info("Bob Private (b)", bob.privatekey)

    # Alice -> Bob
    alice_pub = alice.get_public_hex()
    print_info("Alice Public (A = G^a mod P)", alice_pub)
    key_for_bob = net.send("Alice", "Bob", alice_pub)

    # Bob -> Alice
    bob_pub = bob.get_public_hex()
    print_info("Bob Public (B = G^b mod P)", bob_pub)
    key_for_alice = net.send("Bob", "Alice", bob_pub)

    # Step 2: Establish shared secret
    print_step("Step 2: Establishing Sessions")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    print(" [Status]: Shared Secret computed: S = B^a mod P = A^b mod P")

    # Step 3: Secure Message Transmission
    print_step("Step 3: Secure Message Transmission")

    message = b"Jimminy Crickets Batman! I just saw a gnome absolutely slime out a guy with his own gun!!!"
    print_info("Alice plaintext", message.decode())

    # Alice generates keystream
    alice_keystream = alice.PRNG.generate(len(message))

    # Encrypt
    encrypted_msg = stream_cipher(message, alice_keystream)
    print_info("Ciphertext (hex)", encrypted_msg.hex())

    # Send over network
    delivered_data = net.send("Alice", "Bob", encrypted_msg)

    # Bob generates same keystream (same shared secret state)
    bob_keystream = bob.PRNG.generate(len(delivered_data))

    # Decrypt
    final_message = stream_cipher(delivered_data, bob_keystream)

    print_info("Bob decrypted", final_message.decode(errors="replace"))


    # ==========================================
    # SCENARIO B: MALICIOUS (MITM) ATTACK
    # ==========================================
    '''
    print_header("SCENARIO B: MALICIOUS (MITM) ATTACK")
    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    net = Network()
    net.mallory = mallory
    print_step("Step 1: Mallory's Parameters")
    print_info("Mallory Private (m)", mallory.private_key)
    print_info("Mallory Public (M)", mallory.public_hex)
    print_step("Step 2: Compromised Key Exchange")
    # Alice sends A -> Mallory Intercepts -> Returns M to Alice
    # Bob sends B -> Mallory Intercepts -> Returns M to Bob
    print("Alice sending key to Bob...")
    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())
    print("Bob sending key to Alice...")
    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())
    print_step("Step 3: Poisoned Shared Secrets")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    # Note: Alice's session uses S1 = M^a, Bob's uses S2 = M^b. Mallory knows both.
    print(" [Alice Session]: S_am = (Mallory_Pub)^a mod P")
    print(" [Bob Session]: S_bm = (Mallory_Pub)^b mod P")
    print_step("Step 4: Interception")
    message = b"Meet me at 9pm."
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    final_message = xor_crypt(delivered_data, bob.session_prng)
    print_info("Bob received", final_message.decode())
    if b"3am" in final_message:
        print("\n[DANGER] MITM SUCCESS: Mallory used her private key (m) to decrypt and re-encrypt.")
    '''

# Main Function
if __name__ == "__main__":
    main()