"""
Classes related to Diffie-Hellman key exchange
"""

from random import randint
from Cryptopals_main import AESCode
from Cryptopals_main import rand_bytes
from SHA_1 import sha_1
from hashlib import sha256
import hmac

# Large number operations
def power_mod(b, e, m):
    # Calculates b**e % m, useful for large numbers
    x = 1
    while e > 0:
        # Calculate b to the power of powers of two
        # Simulatneously decompose e into powers of two
        b, e, x = (
            b * b % m,
            e // 2,
            b * x % m if e % 2 else x
        )

    return x

# Classes
class DHSender:
    """Sender in a standard Diffie-Hellman key exchange protocol
    DHSender will agree upon a key with DHReceiver
    DHSender can send an ecnrypted message and receive and decrypt a reply

        Attributes
        ----------
        msg_to_send: str
            Message to be sent via encryption
        p: int
            Large prime number
        g: int
            A primitive root mod p
        a: int
            A random integer mod p.
            This integer is kept private.
        A: int
            A = g**a mod p
            This integer will be public.
        B: int
            To be declared by the receiver.
            B = g**b mod p, where b is a random integer mod p kept secret by the receiver
        s: int
            Once B is declared by the receiver, sender can generate s = B**a mod p
            The receiver generates the same number s via s = A**b mod p
        key: bytes
            A key obtained by hashing s in some fashion
        iv: bytes
            Initialisation vector used for CBC encryption
        encode: AESCode
            Holds cipher and message to be encoded.
            Generates the cipher text.
        rec_msg: bytes
            Reply sent by receiver (encrypted using agreed upon cipher)
        decode: AESCode
            Holds cipher and rec_msg.
            Used to decode rec_msg.

        Parameters
        ----------
        msg: str
            Message to be sent via encryption
        p: int
            Large prime number
        g: int
            A primitive root mod p
    """
    def __init__(self, msg: str,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2):
        self.msg_to_send = msg
        self.p = p
        self.g = g
        self.a = randint(0, p - 1)
        self.A = power_mod(g, self.a, p)
        self.B = None
        self.s = None
        self.key = None
        self.iv = None
        self.encode = None
        self.rec_msg = None
        self.decode = None

    def gen_encode(self):
        # Generates AESCode instance holding message to be encrypted along with cipher
        # AESCode method self.cbc_encrypt() will be used to generate cipher text
        code = AESCode(self.msg_to_send, 'text', key=self.key, iv='random')
        return code

    def gen_decode(self):
        # Generates AESCode instance holding message to be deciphered along with cipher
        # AESCode method self.solve() will be used to obtain plaintext
        code = AESCode(self.rec_msg, key=self.key, iv=self.iv)

        return code

    def gen_s(self):
        # Returns integer sender and receiver have agreed upon,
        # from which a key will be hashed
        return power_mod(self.B, self.a, self.p)

    def gen_key(self):
        # From the integer self.s, generates a key to be used for encryption
        int_as_bytes = self.s.to_bytes(192, 'big')  # Transform integer to bytes

        return sha_1(int_as_bytes)[0:16]  # Hash and return 16-byte key

class DHReceiver:
    """Receiver in a standard Diffie-Hellman key exchange protocol
        DHReceiver will agree upon a key with DHSender
        DHReceiver can receive and decrypt an ecnrypted from DHSender
        DHReceiver can send a reply

        Attributes
        ----------
        p: int
            Large prime number
        g: int
            A primitive root mod p
        b: int
            A random integer mod p.
            This integer is kept private.
        B: int
            A = g**b mod p
            This integer will be public.
        A: int
            To be declared by the sender.
            A = g**a mod p, where a is a random integer mod p kept secret by the sender
        s: int
            Once A is declared by the sender, receiver can generate s = A**b mod p
            The sender generates the same number s via s = B**a mod p
        key: bytes
            A key obtained by hashing s in some fashion
        iv: bytes
            Initialisation vector used for CBC encryption, chosen by sender
        rec_msg: bytes
            Message sent by sender (encrypted using agreed upon cipher)
        decode: AESCode
            Holds cipher and rec_msg.
            Used to decode rec_msg.
        reply: str
            Receiver's reply
        encode: AESCode
            Holds cipher and reply to be encoded.
            Generates the cipher text.

        Parameters
        ----------
        p: int
            Large prime number
        g: int
            A primitive root mod p
    """
    def __init__(self,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2):
        self.p = p
        self.g = g
        self.b = randint(0, p - 1)
        self.B = power_mod(g, self.b, p)
        self.A = None
        self.s = None
        self.key = None
        self.iv = None
        self.rec_msg = None
        self.decode = None
        self.reply = None
        self.encode = None

    def gen_decode(self):
        # Generates AESCode instance holding message to be deciphered along with cipher
        # AESCode method self.solve() will be used to obtain plaintext
        code = AESCode(self.rec_msg, key=self.key, iv=self.iv)

        return code

    def gen_encode(self):
        # Generates AESCode instance holding message to be encrypted along with cipher
        # AESCode method self.cbc_encrypt() will be used to generate cipher text
        code = AESCode(self.reply, 'text', key=self.key, iv=self.iv)

        return code

    def gen_s(self):
        # Returns integer sender and receiver have agreed upon,
        # from which a key will be hashed
        return power_mod(self.A, self.b, self.p)

    def gen_key(self):
        # From the integer self.s, generates a key to be used for encryption
        int_as_bytes = self.s.to_bytes(192, 'big')  # Transform integer to bytes

        return sha_1(int_as_bytes)[0:16]  # Hash and return 16-byte key

class DHMITM:
    def __init__(self,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2):
        self.p = p
        self.g = g
        self.A = None
        self.B = None
        self.A_msg = None
        self.B_msg = None
        self.s = 0
        self.key = self.gen_key()
        self.iv = None

    def gen_key(self):
        # From the integer self.s, generates a key to be used for encryption
        int_as_bytes = self.s.to_bytes(192, 'big')  # Transform integer to bytes

        return sha_1(int_as_bytes)[0:16]  # Hash and return 16-byte key

class Server:
    def __init__(self, email: bytes, password: bytes,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2, k=3):
        self.N = p
        self.g = g
        self.k = k
        self.E = email
        self.P = password
        self.salt = self.gen_salt()
        self.v = self.gen_v()  # Password verifier
        self.A = None
        self.b = randint(0, p)
        self.B = (k * self.v + power_mod(g, self.b, p)) % p
        self.u = None  # Random scrambling parameter
        self.K = None
        self.h = None

    def gen_salt(self):
        # Generates a 64-bit salt
        return rand_bytes(8)

    def gen_v(self):
        # Password verifier

        # Create private key
        xH = sha256(self.salt + self.P)  # Hash salt|password
        x = int(xH.hexdigest(), 16)  # Convert hash to integer

        return power_mod(self.g, x, self.N)

    def gen_u(self):
        # Random scrambling parameter
        uH = sha256(str(self.A).encode() + str(self.B).encode())  # Hash A|B
        u = int(uH.hexdigest(), 16)  # Convert hash to integer

        return u

    def gen_K(self):
        S = power_mod(self.A * power_mod(self.v, self.u, self.N),
                      self.b, self.N)
        K = sha256(str(S).encode()).digest()

        return K

    def gen_h(self):
        # Calculates session key
        return hmac.new(self.K, self.salt, sha256).digest()

class Client:
    def __init__(self, email: bytes, password: bytes,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2, k=3):
        self.N = p
        self.g = g
        self.k = k
        self.E = email
        self.P = password
        self.salt = None
        self.a = randint(0, p)
        self.A = power_mod(g, self.a, p)
        self.B = None
        self.u = None  # Random scrambling parameter
        self.K = None

    def gen_u(self):
        # Random scrambling parameter
        uH = sha256(str(self.A).encode() + str(self.B).encode())  # Hash A|B
        u = int(uH.hexdigest(), 16)  # Convert hash to integer

        return u

    def gen_K(self):
        xH = sha256(self.salt + self.P)  # Hash salt|password
        x = int(xH.hexdigest(), 16)  # Convert hash to integer
        S = power_mod((self.B - self.k * power_mod(self.g, x, self.N)),
                      self.a + self.u * x, self.N)
        K = sha256(str(S).encode()).digest()  # Convert int S to bytes and hash

        return K
