"""
Diffie-Hellman Key Exchange (MODP Group 14 - 2048 bit, RFC 3526)
Demonstrates asymmetric session key establishment over an untrusted channel.
Alice and Bob each generate a private integer, exchange public values,
and independently calculate the exact same shared secret without transmitting it.
"""
import os
import secrets

# RFC 3526 2048-bit MODP Group 14 Prime
RFC_3526_2048_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
RFC_3526_2048_PRIME = int(RFC_3526_2048_PRIME_HEX, 16)
RFC_3526_GENERATOR = 2

class DiffieHellman:
    """
    Educational Diffie-Hellman Key Exchange Manager.
    Allows inspection of mathematical steps: p, g, private a/b, public A/B, and shared secret.
    """
    def __init__(self, p: int = RFC_3526_2048_PRIME, g: int = RFC_3526_GENERATOR):
        self.p = p
        self.g = g
        # Generate private key: random 256-bit integer
        self.private_key = secrets.randbelow(self.p - 3) + 2
        # Public key: A = g^a mod p
        self.public_key = pow(self.g, self.private_key, self.p)

    def get_public_hex(self) -> str:
        """Returns public key formatted as hex string for network transmission."""
        return hex(self.public_key)[2:]

    def get_private_hex(self) -> str:
        """Returns private key formatted as hex string (must stay local!)."""
        return hex(self.private_key)[2:]

    def compute_shared_secret(self, peer_public_hex: str) -> bytes:
        """
        Computes Shared Secret S = (peer_public_key)^private_key mod p
        Returns big-endian bytes representation of the shared secret.
        """
        peer_public_int = int(peer_public_hex, 16)
        if not (1 < peer_public_int < self.p - 1):
            raise ValueError("Invalid peer public key: outside subgroup bounds")
        
        shared_int = pow(peer_public_int, self.private_key, self.p)
        # Convert integer to bytes (256 bytes for 2048-bit prime)
        byte_length = (self.p.bit_length() + 7) // 8
        shared_bytes = shared_int.to_bytes(byte_length, byteorder="big")
        return shared_bytes

    def get_parameters_dict(self) -> dict:
        """Returns parameters formatted for inspection and relay."""
        return {
            "p_hex": hex(self.p)[2:],
            "g": self.g,
            "public_key_hex": self.get_public_hex(),
            "bit_length": self.p.bit_length()
        }
