"""
Cryptopals
Created on 23/06/2022
@author: Lawrence Arscott
"""

## Converting from hex to base 64

from random import randint
from numpy import product as prod
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import path


# Byte operations
def hex_byte_hamming(hex1, hex2):
    # Returns the Hamming distance of 2 bytes written in hex
    assert len(hex1) == len(hex2) == 2
    counter = 0
    bin1 = binary(hex1, 16)
    bin2 = binary(hex2, 16)
    for i in range(len(bin1)):
        counter += (int(bin1[i]) + int(bin2[i])) % 2

    return counter

def hex_hamming(hex1, hex2):
    # Returns the Hamming distance between two hex strings

    assert len(hex1) == len(hex2)

    # Convert strings to lists of bytes (strings of length two since hex)
    byte_list_1 = strtotwos(hex1)
    byte_list_2 = strtotwos(hex2)

    # Sum the individual Hamming distances between the bytes
    ham = 0
    for j in range(len(byte_list_1)):
        ham += hex_byte_hamming(byte_list_1[j], byte_list_2[j])

    return ham

def xorb(ba1: bytes, key: bytes):
    # Returns ba1 XOR key, where arguments are b strings
    # https://nitratine.net/blog/post/xor-python-byte-strings/
    key = resize_key(key, len(ba1))
    return bytes([_a ^ _b for _a, _b in zip(ba1, key)])

def bit_flip(bstring, byte_pos_list):
    # Given a bytes string, XORs nth byte with b'\x01' (00000001)

    flip_str = b''  # This will be XORed with bstring
    # Create a byte string with \x01 in the positions given by byte_pos_list padded with zeros
    for i in range(len(bstring)):
        if i in byte_pos_list:
            flip_str += b'\x01'
        else:
            flip_str += b'\x00'

    return EasyByte(bstring).xor(flip_str).b

def binary(n, scale):
    # Converts integer base scale to a single byte
    """
    Parameters
    ----------
    n : str
        Integer to be converted (must be between 0 and 255)
        Given as a str in some base
    scale : int
        Base to which n is to be taken

    Returns
    -------
    str
        Byte
    """
    assert 0 <= int(n, scale) < 256  # So that integer may be written as a byte
    return bin(int(n, scale))[2:].zfill(8)

def rand_bytes(n: int):
    # Returns a byte string composed of n random bytes
    rand = b''
    for i in range(n):
        rand_int = randint(0, 255)  # Obtain random integer representing a byte
        rand += rand_int.to_bytes(1, 'big')  # to_bytes: int -> byte
    return rand

def b_remove(b: bytes, rem: bytes) -> bytes:
    # Removes all characters in the bstring rem from the bstring s, returns s
    for i in range(len(rem)):
        c = rem[i:i+1]
        b = b.replace(c, b'')

    return b

def gen_sandwich(prep=b'', app=b'', rem=b'') -> callable:
    # Generates a function that removes characters in rem from a bstring b,
    # prepends prep to the result and appends app to it
    def sandwich(b: bytes) -> bytes:
        # Removes characters in rem from prep and app, prepends prep and appends app to s, and returns s

        return prep + b_remove(b, rem) + app

    return sandwich

def user_profile_for(email: bytes):
    # Used in challenge 2-13
    # Encodes a user profile as a byte
    email = b_remove(email, b'&=')
    return 'email='.encode() + email + f'&uid='.encode() + \
           str(randint(0, 9999)).zfill(4).encode() + '&role=user'.encode()

def create_rand_byte_fun(txtdoc, base=None):
    # Returns a function that returns a random line in txtdoc as a byte
    # base gives basis in which the file is encoded (see class EasyByte)
    def rand_byte():
        return EasyByte(rand_line(txtdoc), base)

    return rand_byte

# Text formatting
def single_line_read2(txtfile: str):
    # Reads file as a single line (stripping newlines)
    with open(txtfile) as file:
        sngl_line = ''.join([line.rstrip('\n') for line in file])
    return sngl_line

def resize_key(key, n):
    # Resize key to length n by repeating
    new_key = key * (n // len(key) + 1)

    return new_key[:n]  # Chop off excess

def strtotwos(s: str, n=2):
    # Splits string into list of strings of length 2
    return [s[i:i+n] for i in range(0, len(s), n)]

def str_split(text: str, n: int):
    # From a string, returns a list of strings consisting of every nth character,
    # starting from character 0, ..., n-1
    return [text[i::n] for i in range(n)]

def string_to_dict(s, sep1='=', sep2='&'):
    # Takes string of form 'key1=value1&key2=value2&...' and returns dict
    # of form {'key1': 'value1', 'key2': 'value2', ...}
    lst = [x.split(sep1) for x in s.split(sep2)]

    return {two_lst[0]: two_lst[1] for two_lst in lst}

def rand_line(txtdoc):
    # Returns random line in .txt file
    with open(txtdoc) as file:
        lines = file.readlines()
        return lines[randint(0, len(lines) - 1)]  # Remembering lists are indexed 0 to length - 1

# Tests
def count_special_character(string):
    # Returns the number of special characters in a string
    # (Does not count spaces)
    special_char = 0

    for i in range(0, len(string)):
        ch = string[i]
        if not ch.isalpha() and not ch.isdigit() and ch != ' ':
            special_char += 1

    return special_char

def simple_space_test(ans: str, freq=10):
    # Tests whether the number of spaces in the answer is plausible
    n = len(ans)//freq  # For every freq characters, require a space
    return ans.count(' ') >= n

def simple_ch_test(ans: str, freq=7):
    # Tests whether string has too many special characters
    n = len(ans)//freq + 1
    return count_special_character(ans) < n

# Classes
class EasyByte:
    """Class for the manipulation of byte strings

    Attributes
    ----------
    b : bytes
        Bytes string

     Parameters
    ----------
    code : str or .txt file
        Code to be converted to byte. This may be a string or a .txt file.
        May be encoded in a variety of formats, see base.
    base : str, optional
        Base in which the code is encoded.
        If not given, it is assumed the code is already in byte format.
        May otherwise be 'text' for text, 'hex' for hexadecimal or 'b64' for base64
        """
    def __init__(self, code, base=None):
        self.b = EasyByte.make_byte(self, code, base)

    def make_byte(self, code, base=None):
        # Translate string in multiple formats to byte string
        # If a file is given, the file is first converted to a single line string
        if path.isfile(code):
            return EasyByte.make_byte(self, single_line_read2(code), base)

        elif not base:
            return code

        elif base == 'text':
            return code.encode()

        elif base == 'hex':
            return bytes.fromhex(code)

        elif base == 'b64':
            return b64decode(code)

        else:
            raise Exception('Unknown format')

    def convert(self, base=None):
        # Returns byte converted to string according to base
        if not base:
            return self.b

        elif base == 'text':
            return self.b.decode()

        elif base == 'hex':
            return self.b.hex()

        elif base == 'b64':
            # The following works since A-Z,a-z,+,/ represent bytes that decode into that symbol
            return b64encode(self.b).decode()

        else:
            raise Exception('Unknown format')

    def xor(self, key, base=None):
        # XORs the byte according to 'key' in 'base' format.
        key = EasyByte.make_byte(self, key, base)

        return EasyByte(xorb(self.b, key))

    def hamming(self, b2, base=None):
        # Returns the Hamming distance between the byte and a second byte 'b2',
        # encoded according to 'base'.
        b2 = EasyByte(b2, base)
        return hex_hamming(self.convert('hex'), b2.convert('hex'))

class VCode:
    """Class for the manipulation of messages encoded with a Vigenère cipher

    Attributes
    ----------
    easybyte : EasyByte
        See class EasyByte

    Parameters
    ----------
    code : str or .txt file
        Message. May be passed as a .txt file
        May be plain text or encrypted
        Purpose of the class is to then encrypt or decrypt 'code'
    base : str, optional
        Base in which the code is encoded.
        If not given, it is assumed the code is in byte format.
        May otherwise be 'text' for text, 'hex' for hexadecimal or 'b64' for base64
        """
    def __init__(self, code, base=None):
        self.easybyte = EasyByte(code, base)
        self.key = None
        self.keys = None
        self.key_poss = None

    def gen_keys(self, space_test=True, char_test=True, keys=None):
        # Given a list of keys, assigns those that pass tests to self.keys
        self.keys = VCode.test_keys(self, keys, space_test, char_test)
        return self

    def use_keys(self):
        # Prints byte decrypted against all keys in self.keys as text
        for key in self.keys:
            print(self.easybyte.xor(key).convert('text'))

    def single_byte_keys(self, space_test=True, char_test=True):
        # Assigns plausible single byte keys to self.keys
        keys = [int(i).to_bytes(1, byteorder='big') for i in range(256)]
        self.keys = self.test_keys(keys, space_test, char_test)
        return self

    def test_keys(self, keys, space_test=True, char_test=True):
        # Given a list of keys, returns a list of those which pass all tests
        passed = []
        for key in keys:
            try:
                s = self.easybyte.xor(key).convert('text')

                # Check whether answer passes tests before yielding
                if not space_test or simple_space_test(s):
                    if not char_test or simple_ch_test(s):
                        passed.append(key)

            except ValueError:  # Sometimes there is no corresponding ASCII unicode character
                pass

        return passed

    def key_length(self, m=1, n=40):
        # Prints a score for each key length
        # Low score is more plausible
        for i in range(1, n):
            ham = 0

            for k in range(m):
                indent = 2 * k * i
                chunk1 = EasyByte(self.easybyte.b[indent:indent + i])
                chunk2 = EasyByte(self.easybyte.b[indent + i: indent + 2 * i])
                assert len(chunk1.b) == len(chunk2.b)

                ham += chunk1.hamming(chunk2.b)

            print(str(i) + ' has score ' + str(ham / i / m))

    def split(self, key_l: int):
        # Divides the message into strips according to the key length,
        # so as to obtain key_l single byte encoded strips
        return [VCode(byte_i) for byte_i in str_split(self.easybyte.b, key_l)]

    def find_v_key(self, key_l):
        # Given a key length, assigns plausible Vigenère keys of that length
        # to self.key_poss
        print(f'Searching for repeating key of length {key_l}')
        strips = self.split(key_l)
        keys_by_strip = []

        for strip in strips:
            keys_by_strip.append(strip.single_byte_keys(True, True).keys)

        possibilities = prod([len(keys) for keys in keys_by_strip])
        print(f"Found {possibilities} plausible key(s)")

        self.key_poss = keys_by_strip
        return self

    def keys_from_poss(self):
        # From self.key_poss, which contains possibilities for each byte of the key,
        # assigns possible keys to self.keys, or if only 1 possible key, assigns to self.key
        keys = [sing_byte for sing_byte in self.key_poss[0]]
        for i in range(1, len(self.key_poss)):
            keys = [old_key + new_byte for old_key in keys for new_byte in self.key_poss[i]]

        if len(keys) > 1:
            print('Several keys.')
            self.keys = keys

        if len(keys) == 1:
            print('Only 1 key !')
            self.key = keys[0]

        else:
            raise Exception("Error: no keys ?")

    def solve(self):
        # Prints code decyphered according to self.key
        print(self.easybyte.xor(self.key).convert('text'))

    def freq(self):
        # Returns the frequency of each byte in the encoded message
        freqs = [0]*256
        for byt in self.easybyte.b:
            # Each byt is an integer representing ord(byte)
            freqs[byt] += 1

        return freqs

    def simple_freq_test(self, lb_max_freq=10):
        # Simple frequency test to detect Vigenère ciphers
        # Expects most common byte to appear once in every lb_max_freq bytes
        # You would expect a fair amount of spaces, for example
        freqs = self.freq()

        return max(freqs) > len(self.easybyte.b) / lb_max_freq

class ListVCode:
    """Class to deal with multiple messages, passed as lines in a .txt file

    Attributes
    ----------
    codes : list of VCode
        See class VCode

    Parameters
    ----------
    code_file : .txt file
        Message, passed as a .txt file
    base : str, optional
        Base in which the code is encoded.
        If not given, it is assumed the code is in byte format.
        May otherwise be 'text' for text, 'hex' for hexadecimal or 'b64' for base64
    """
    def __init__(self, code_file, base=None):
        with open(code_file) as file:
            self.codes = [VCode(line, base) for line in file]

    def detect_single_byte(self):
        # Prints the line number of codes possibly encrypted with a single byte repeating key
        # Decrypts those lines
        for i in range(len(self.codes)):
            code = self.codes[i]

            # Run code through simple singly byte key detection
            if code.simple_freq_test():
                print(i)

                # If passes, then decrypt
                code = code.single_byte_keys()
                code.use_keys()

class AESCode:
    """Class for the manipulation of messages encoded with AES

    Attributes
    ----------
    easybyte : EasyByte
        See class EasyByte

    cipher : Crypto.Cipher._mode_ecb.EcbMode
        ECB Cipher, generated by key, to encode/decode message contained in 'code'

    iv : bytes
        Initialisation vector, used in CBC mode

    Parameters
    ----------
    code : str or .txt file
        Message. May be passed as a .txt file
        May be plain text or encrypted
        Purpose of the class is to then encrypt or decrypt 'code'
    base : str, optional
        Base in which the code is encoded.
        If not given, it is assumed the code is in byte format.
        May otherwise be 'text' for text, 'hex' for hexadecimal or 'b64' for base64
    """
    def __init__(self, code=b'', base=None, key=None, iv=None):
        self.easybyte = EasyByte(code, base)
        self.cipher = None
        self.iv = None
        if key:
            self.cipher = self.gen_cipher(key)
        if iv:
            self.iv = self.gen_iv(iv)

    def gen_cipher(self, key):
        # Generates cipher according to key
        # May request random key by entering key as the string 'random'
        if key == 'random':
            key = rand_bytes(16)
        elif type(key) == bytes:
            pass
        else:
            raise Exception('TypeError')
        return AES.new(key, AES.MODE_ECB)

    def gen_iv(self, iv):
        if iv == 'random':
            iv = rand_bytes(16)
        elif type(iv) == bytes:
            pass
        else:
            raise Exception('TypeError')
        return iv

    def ecb_solve(self, letsunpad=True):
        # Returns message decrypted according to self.cipher
        ans = self.cipher.decrypt(self.easybyte.b)

        # Unpad removes padding originally added to make the message a multiple of 128 bits
        if letsunpad:
            ans = unpad(ans, AES.block_size)

        return ans.decode()

    def block_list(self, n=16):
        # Returns list of code byte seperated into bytes of length n
        blen = len(self.easybyte.b)
        assert blen % n == 0
        nblocks = blen//n
        return [EasyByte(self.easybyte.b[n*i:n*i + n]) for i in range(nblocks)]

    def repeat(self):
        # Counts how many times blocks repeat when code byte is separated into blocks
        count = 0
        blocks = self.block_list()
        for i in range(len(blocks) - 1):
            for j in range(i + 1, len(blocks)):
                if blocks[i].b == blocks[j].b:
                    count += 1
        return count

    def ecb_encrypt(self, padding=True):
        # Encodes message according to key
        if padding:
            self.easybyte.b = pad(self.easybyte.b, AES.block_size)
        self.easybyte.b = self.cipher.encrypt(self.easybyte.b)
        return self

    def cbc_encrypt(self):
        # Encrypt according to CBC cipher generated by key, iv
        self.easybyte.b = pad(self.easybyte.b, AES.block_size)  # pad
        blocks = self.block_list()
        prev_cipher_block = self.iv
        gibberish = b''
        for i in range(len(blocks)):
            new_easybyte = blocks[i].xor(prev_cipher_block)
            new_code = self.cipher.encrypt(new_easybyte.b)
            gibberish += new_code
            prev_cipher_block = new_code
        self.easybyte = EasyByte(gibberish)
        return self

    def cbc_solve(self):
        # Decrypt according to cbc cipher generated by self.key and self.iv
        blocks = self.block_list()
        sol = b''
        for i in range(1, len(blocks)):
            deciphered = self.cipher.decrypt(blocks[i].b)
            unxored = xorb(deciphered, blocks[i-1].b)
            sol += unxored
        pos1deciphered = self.cipher.decrypt(blocks[0].b)
        pos1unxored = xorb(pos1deciphered, self.iv)
        sol = pos1unxored + sol
        sol = unpad(sol, AES.block_size)
        print(sol)
        return sol

    def gen_ecb_oracle(self, bstr_fun: callable):
        # Generates an oracle function according to bstr_fun, see below
        def ecb_oracle(bstring: bytes):
            # First manipulates bstring according to bstr_fun
            # Then ecb encrypts according to cypher
            to_be_encrypted = pad(bstr_fun(bstring), AES.block_size)
            return self.cipher.encrypt(to_be_encrypted)

        return ecb_oracle

    def gen_cbc_oracle(self, bstr_fun: callable):
        # Generates an oracle function according to bstr_fun, see below

        def cbc_oracle(bstring: bytes):
            # First manipulates bstring according to bstr_fun
            # Then cbc encrypts according to cypher
            self.easybyte.b = bstr_fun(bstring)
            return self.cbc_encrypt().easybyte.b

        return cbc_oracle

    def gen_cbc_oracle_rand(self, eb_gen_fun: callable):
        # Define a cbc oracle that encrypts a random byte string generated by fun
        def oracle():
            self.easybyte = eb_gen_fun()
            return self.cbc_encrypt().easybyte.b

        return oracle

class ListECB:
    """Class to deal with multiple messages, passed as lines in a .txt file

    Attributes
    ----------
    codes : list of AESCode
        See class AESCode

    Parameters
    ----------
    code_file : .txt file
        Message, passed as a .txt file
    base : str, optional
        Base in which the code is encoded.
        If not given, it is assumed the code is in byte format.
        May otherwise be 'text' for text, 'hex' for hexadecimal or 'b64' for base64
    """
    def __init__(self, code_file, base=None):
        with open(code_file) as file:
            self.codes = [AESCode(line, base) for line in file]

    def simple_repeat_test(self):
        # Tests each byte array in the list self.codes for repeats when split into blocks
        for k in range(len(self.codes)):
            repeat_k = self.codes[k].repeat()
            if repeat_k != 0:
                print(f'Code {k} has {repeat_k} repeats')

class Profile:
    """Class for profile creation

    Attributes
    ----------
    p : str
        Profile encoded as single string
        Example: email=foo@bar&uid=10&role='user'

    Parameters
    ----------
    email : str
        Profile's email
    role : str
        Profile's role, may be user or admin.
    """
    def __init__(self, email: bytes, role='user'):
        assert role == 'user' or role == 'admin'
        email = b_remove(email, b'&=')
        s = f'email={email}&uid={str(randint(0, 9999))}&role={role}'

        self.p = s

class DetOracle:
    """Class for oracle functions of deterministic encryption

        Attributes
        ----------
        fun : callable
            Oracle function
            Takes a string, modifies it according to a predetermined function,
            returns result encrypted according to a deterministic cypher

        Parameters
        ----------
        fun : callable
            Oracle function to be worked on
    """
    def __init__(self, fun: callable):
        self.fun = fun
        self.b_size = None
        self.l_full_prep_blocks = None
        self.prep_fill = None
        self.og_fun = None
        self.clean_fun = None

    def max_unchanged(self):
        # Returns the number of leading characters unaffected when passing any byte to the oracle
        # Warning: 1/256 chance of error
        b1 = self.fun(b'A')
        b2 = self.fun(b'B')

        for i in reversed(range(len(b1))):
            if b1[i] != b2[i]:
                return i + 1

    def block_size(self, max_n=64):
        # Takes an oracle function
        # Returns its block size, and the length of prepended text occupying full blocks
        b_size = 0
        max_unchanged = self.max_unchanged()

        # Obtain a function that "forgets" the initial bytes that don't change
        snipped_fun = self.mod_oracle(l_snip=max_unchanged)

        # Pass bytes of growing length to the "cleaned up" oracle until we observe repeats
        for i in range(1, max_n + 1):
            indent = b'A' * i
            if snipped_fun(b'') == snipped_fun(indent)[i:]:
                b_size = i
                break

        # Check we found a solution
        if b_size == 0:
            raise Exception(f'No blocksize less than {max_n} found')

        # The leading unchanged bytes should have length a multiple of the block size
        assert max_unchanged % b_size == 0

        # The number of leading unchanging blocks is the largest multiple of
        # the block size contained in the number of unchanging bytes
        l_full_prep_blocks = (max_unchanged//b_size - 1) * b_size

        return b_size, l_full_prep_blocks

    def fill_prepended(self):
        # returns a byte string to fill any unfull blocks containing prepended random text
        l_fill_prepended = (self.b_size - self.l_prepended()) % 16
        return b'' + l_fill_prepended * b'A'

    def l_prepended(self):
        # Returns the length of prepended text (not counting that contained in full blocks)

        # Use oracle function without full blocks
        snipped_fun = self.mod_oracle(l_snip=self.l_full_prep_blocks)

        # Find out the length a byte passed to the oracle needs to be to start affecting the second block
        # instead of the first.
        # NOTE: Should probably flip this around to consider the case 0 first
        for i in range(1, self.b_size):
            if snipped_fun(b'A' * (i + 1))[0:self.b_size] == snipped_fun(b'A' * i + b'B')[0:self.b_size]:
                return (-i) % self.b_size

        return 0

    def mod_oracle(self, l_snip=0, prep=b''):
        # Returns a modified oracle function for lighter code
        def modified(bstring: bytes):
            return self.fun(prep + bstring)[l_snip:]

        return modified

    def clean_oracle(self):
        # 'Cleans up' oracle function to obtain a simpler case to crack a solution for

        # Obtain total length of prepended text
        to_chop = self.l_full_prep_blocks
        if len(self.prep_fill):
            to_chop += self.b_size

        # Obtain an oracle function without prepended text
        # This is done by passing a byte filling any block partially filled with prepended text.
        # We can then chop off unwanted text in units of block size
        return self.mod_oracle(to_chop, self.prep_fill)

    def solve(self):
        # With access to an oracle function,
        # prints the encrypted message, discarding any prepended random blocks

        # Prepare
        self.b_size, self.l_full_prep_blocks = self.block_size()
        self.prep_fill = self.fill_prepended()
        self.og_fun = self.fun
        self.clean_fun = self.clean_oracle()

        print(f'Block size is {self.b_size}')

        self.solve_clean()

    # TODO: Break down
    # Would be best to modify the oracle each time
    def solve_clean(self):
        # With access to an oracle function, prints the encrypted message
        oracle = self.clean_fun  # Operate on simple oracle without prepended random text
        n_blocks = len(oracle(b'')) // self.b_size  # Number of blocks
        sol = b''

        # Iterate over blocks
        for k in range(n_blocks):
            indent = k * self.b_size  # Indent to work on different blocks

            # Iterate over bytes in block
            for i in range(self.b_size):
                dummy = b'A' * (self.b_size - 1 - i)

                find = oracle(dummy)[indent:self.b_size + indent]
                new_byte = None
                for j in range(256):
                    byt = dummy + sol + j.to_bytes(1, 'big')
                    if oracle(byt)[indent:self.b_size + indent] == find:
                        new_byte = j.to_bytes(1, 'big')
                        break

                # When we each the end of the message, the oracle will start padding
                if new_byte == b'\x01' and k == n_blocks - 1:
                    print('stopped')
                    break

                # Add new byte to solution
                sol += new_byte

        print(sol)

    def challenge2_5(self):
        # Function specific to challenge 2.5
        email1 = b'YELLOWBIRD' + pad(b'admin', AES.block_size)
        admin_block = self.fun(email1)[16:32]

        email2 = b'YELLOWBIRDS'
        admin = self.fun(email2)[:32] + admin_block

        return admin
