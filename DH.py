"""
Classes related to Diffie-Hellman key exchange
Now with subclasses.
"""

from random import randint
from Cryptopals_main import AESCode
from Cryptopals_main import rand_bytes, disc_log
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

# Check SHA-256 HMAC
def check_hmac(c_text: bytes, key: bytes):
    # Message authentification
    # Checks the received ciphertext is of form:
    # ciphertext | SHA256-HMAC(key|ciphertext)

    # Separate received bytes into ciphertext and mac
    msg = c_text[:-32]
    mac = c_text[-32:]  # SHA256 -> 32 bytes

    # Perform check: return True or False for pass or fail
    return mac == hmac.new(key, msg, sha256).digest()

class DH:
    """General class for a standard Diffie-Hellman key exchange protocol
    Instances to be created with subclasses DHSender, DHReceiver, DHMITM, DHAttacker
    Standard protocol:
    DHSender will agree upon a key with DHReceiver
    DHSender can send an ecnrypted message and receive and decrypt a reply

    Attributes
    ----------
    p: int
        Large prime number
    g: int
        A primitive root mod p
    q: int
        The order of g mod p if known (and not p)
    A: int
        A = g**a mod p
        To be declared by the sender. This integer will be public.
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

    Parameters
    ----------
    p: int
        Large prime number
    g: int
        A primitive root mod p
    q: int
        The order of g mod p if known (and not p)
    """
    def __init__(self,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2, q=None):
        self.p = p
        self.g = g
        self.q = q if q is not None else p
        self.A = None
        self.B = None
        self.s = None
        self.key = None
        self.iv = None

    def gen_key(self):
        # From the integer self.s, generates a key to be used for encryption
        int_as_bytes = str(self.s).encode()  # Transform integer to bytes

        return sha256(int_as_bytes).digest()[0:16]  # Hash and return 16-byte key

    def gen_code(self, msg):
        # Generates AESCode instance holding message to be encrypted/decrypted along with cipher
        # AESCode method self.cbc_encrypt()/self.cbc_solve() will be used
        code = AESCode(msg, key=self.key, iv=self.iv)

        return code

    def gen_decode_hmac(self, ciphertext):
        # Decode ciphertext that has an appended hmac
        msg = ciphertext[:-32]
        mac = ciphertext[-32:]

        # Authenticate message
        try:
            assert mac == hmac.new(self.key, msg, sha256).digest()

        except AssertionError:
            print('Authentication Error')

        code = AESCode(msg, key=self.key, iv=self.iv)

        return code

    def add_hmac(self, ciphertext):
        # Generates hmac for encoded reply and appends to ciphertext
        our_hmac = hmac.new(self.key, ciphertext, sha256).digest()

        return ciphertext + our_hmac

class DHSender(DH):
    """The sender for a standard Diffie-Hellman key exchange protocol

    Attributes
    ----------
    a: int
        A random integer between 1 and q
    encode: AESCode
        Holds cipher and message to be encoded.
        Used to generate the cipher text.
    rec_msg: bytes
        Reply sent by receiver (encrypted using agreed upon cipher)
    decode: AESCode
        Holds cipher and rec_msg.
        Used to decode rec_msg.

    Parameters
    ----------
    msg: bytes
        Message to be sent (plaintext)
    """
    def __init__(self, msg: bytes,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2, q=None):
        self.msg_to_send = msg
        super().__init__(p, g, q)
        self.a = randint(0, self.q - 1)
        self.A = power_mod(g, self.a, p)
        self.encode = None
        self.rec_msg = None
        self.decode = None
        self.rec_msg = None
        self.iv = rand_bytes(16)

    def gen_s(self):
        # Returns integer sender and receiver have agreed upon,
        # from which a key will be hashed
        return power_mod(self.B, self.a, self.p)

class DHReceiver(DH):
    """Receiver in a standard Diffie-Hellman key exchange protocol

    Attributes
    ----------
    b: int
        A random integer between 1 and q
    encode: AESCode
        Holds cipher and reply to be encoded.
        Used to generate the cipher text.
    rec_msg: bytes
        Message sent by sender (encrypted using agreed upon cipher)
    decode: AESCode
        Holds cipher and rec_msg.
        Used to decode rec_msg.
    reply: bytes
        Reply to be sent back (plaintext)

    Parameters
    ----------
    """
    def __init__(self,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2, q=None):
        super().__init__(p, g, q)
        self.b = randint(0, self.q - 1)
        self.B = power_mod(g, self.b, p)
        self.encode = None
        self.rec_msg = None
        self.decode = None
        self.rec_msg = None
        self.reply = None

    def gen_s(self):
        # Returns integer sender and receiver have agreed upon,
        # from which a key will be hashed
        return power_mod(self.A, self.b, self.p)

class DHMITM(DH):
    """Man in the middle: intercepts messages from Alice, modifies them to his convenience
    before passing them on to Bob. In this way, the man in the middle can manipulate the key.

    Attributes
    ----------
    A_msg: bytes
        Message sent by sender (encrypted using agreed upon cipher)
    B_msg: bytes
        Reply sent by receiver (encrypted using agreed upon cipher)
    s: int
        Integer generated by both A and B from which a key is derived.
        MITM wishes to manipulate this.
    key: bytes
        A key obtained by hashing manipulated s in some fashion.

    Parameters
    ----------
    """
    def __init__(self,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2, q=None):
        super().__init__(p, g, q)
        self.A_msg = None
        self.B_msg = None
        self.s = 0
        self.key = self.gen_key()

class DHAttacker(DH):
    """DHAttacker wishes to crack DHReceiver's secret key through multiple interactions.
    Example: Small group confinement attack

    Attributes
    ----------
    rec_msg: bytes
        Message sent by DHReceiver

    Parameters
    ----------
    """
    def __init__(self,
                 p=int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc'
                       '74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f'
                       '14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f4'
                       '06b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8'
                       'a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3'
                       '56208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffff'
                       'ffffffffffff', 16),
                 g=2, q=None):
        super().__init__(p, g, q)
        self.rec_msg = b''
        self.pub_key = None
        self.part_key = None
        self.part_key_mod = None

    def _prep_kangaroo(self):
        # Prepares variables for method kangaroo

        # Transform g
        new_g = pow(self.g, self.part_key_mod, self.p)

        # Calculate inverse of g, using the fact the group has order p-1
        g_inv = pow(self.g, self.p - 2, self.p)
        assert (self.g * g_inv) % self.p == 1  # Check this is an inverse

        # Transform y
        g_to_minus_part_key = pow(g_inv, self.part_key, self.p)
        new_y = (self.pub_key * g_to_minus_part_key) % self.p

        # Calculate greatest x s.t. new_y = new_g**x
        end = (self.q - 1) // self.part_key_mod + 1

        return new_g, new_y, end

    def kangaroo(self):
        # Given our knowledge of defender's private key, (i.e. its modulus modulo some integer <p),
        # and the public key, calculates the private key using:
        # Pollard's Method for Catching Kangaroos

        # Transform variables, obtaining the continuous interval required for the method
        new_g, new_y, end = self._prep_kangaroo()

        # Call kangaroo method
        new_index = disc_log(new_g, 0, end, self.p, new_y)

        # Transform back to get the private key
        ans = (self.part_key + new_index * self.part_key_mod) % self.q

        assert pow(self.g, ans, self.p) == self.pub_key

        return ans

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
        self.salt = self.gen_salt()
        self.v = self.gen_v(password)  # Password verifier
        self.A = None
        self.b = randint(0, p)
        self.B = (k * self.v + power_mod(g, self.b, p)) % p
        self.u = None  # Random scrambling parameter
        self.K = None
        self.h = None

    def gen_salt(self):
        # Generates a 64-bit salt
        return rand_bytes(8)

    def gen_v(self, password):
        # Password verifier

        # Create private key
        xH = sha256(self.salt + password)  # Hash salt|password
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
