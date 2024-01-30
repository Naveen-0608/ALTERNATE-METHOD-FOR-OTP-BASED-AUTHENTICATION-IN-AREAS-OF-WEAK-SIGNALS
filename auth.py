import random
import hashlib
from pyotp import TOTP

class DiffieHellmanAuth:
    def __init__(self):
        self.prime = 23
        self.generator = 5

        self.private_key_client, self.public_key_client = self.diffie_hellman()
        self.private_key_server, self.public_key_server = self.diffie_hellman()

        self.shared_secret_client = self.calculate_shared_secret(self.public_key_server, self.private_key_client)
        self.shared_secret_bytes = self.shared_secret_client.to_bytes((self.shared_secret_client.bit_length() + 7) // 8, byteorder='big')
        self.hmac_key = hashlib.sha256(self.shared_secret_bytes).digest()

        self.totp = TOTP(self.hmac_key, interval=30)

    def diffie_hellman(self):
        private_key = random.randint(1, self.prime - 1)
        public_key = pow(self.generator, private_key, self.prime)
        return private_key, public_key

    def calculate_shared_secret(self, public_key, private_key):
        return pow(public_key, private_key, self.prime)

    def generate_otp(self):
        return self.totp.now()

    def verify_otp(self, otp_input):
        return self.totp.verify(otp_input)
