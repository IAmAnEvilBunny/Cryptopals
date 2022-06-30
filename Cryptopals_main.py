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
    assert len(hex1) == len(hex2)
    counter = 0
    bin1 = binary(hex1, 16)
    bin2 = binary(hex2, 16)
    for i in range(len(bin1)):
        counter += (int(bin1[i]) + int(bin2[i])) % 2

    return counter

def hex_hamming(hex1, hex2):
    # Returns the hamming distance between two hex strings
    byte_list_1 = strtotwos(hex1)
    byte_list_2 = strtotwos(hex2)

    byte_l = len(byte_list_1)
    assert byte_l == len(byte_list_2)

    ham = 0
    for j in range(byte_l):
        ham += hex_byte_hamming(byte_list_1[j], byte_list_2[j])

    return ham

def xorb(ba1, key):
    # Returns ba1 XOR key, where ba1 and key are bytes
    # https://nitratine.net/blog/post/xor-python-byte-strings/
    key = resize_key2(key, len(ba1))
    return bytes([_a ^ _b for _a, _b in zip(ba1, key)])

def binary(n, scale):
    # Converts integer base scale to a byte
    """
    Parameters
    ----------
    n : str
        Integer to be converted (must be between 0 and 255)
    scale : int
        Base to which n is to be taken

    Returns
    -------
    str
        Byte
    """
    assert 0 <= int(n, scale) < 256  # So that integer may be written as a byte
    return bin(int(n, scale))[2:].zfill(8)

def rand_bytes(n):
    # Returns a byte string composed of n random bytes
    rand = b''
    for i in range(n):
        rand_int = randint(0, 255)  # Obtain random integer representing a byte
        rand += rand_int.to_bytes(1, 'big')  # to_bytes: int -> byte
    return rand


# Text formatting
def single_line_read2(txtfile):
    # Reads file as a single line (stripping newlines)
    with open(txtfile) as file:
        sngl_line = ''.join([line.rstrip('\n') for line in file])
    return sngl_line

def resize_key2(key, n):
    # Resize key to length n by repeating
    new_key = key * (n // len(key) + 1)

    return new_key[:n]  # Chop off excess

def strtotwos(s, n=2):
    # Splits string into list of strings of length 2
    return [s[i:i+n] for i in range(0, len(s), n)]

def str_split(text, n):
    # From a string, returns a list of strings consisting of every nth character,
    # starting from character 0, ..., n-1
    return [text[i::n] for i in range(n)]

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

def simple_space_test(ans, freq=10):
    # Tests whether the number of spaces in the answer is plausible
    n = len(ans)//freq  # For every freq characters, require a space
    return ans.count(' ') >= n

def simple_ch_test(ans, freq=7):
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
    def __init__(self, code, base=None):
        self.easybyte = EasyByte(code, base)
        self.key = None
        self.keys = None
        self.key_poss = None

    def gen_keys(self, space_test=True, char_test=True, keys=None):
        self.keys = VCode.test_keys(self, keys, space_test, char_test)

    def use_keys(self):
        for key in self.keys:
            print(self.easybyte.xor(key).convert('text'))

    def single_byte_keys(self, space_test=True, char_test=True):
        keys = [int(i).to_bytes(1, byteorder='big') for i in range(256)]
        self.keys = self.test_keys(keys, space_test, char_test)
        return self

    def test_keys(self, keys, space_test=True, char_test=True):
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
        for i in range(1, n):
            ham = 0

            for k in range(m):
                indent = 2 * k * i
                chunk1 = EasyByte(self.easybyte.b[indent:indent + i])
                chunk2 = EasyByte(self.easybyte.b[indent + i: indent + 2 * i])
                assert len(chunk1.b) == len(chunk2.b)

                ham += chunk1.hamming(chunk2.b)

            print(str(i) + ' has score ' + str(ham / i / m))

    def split(self, n):
        return [VCode(byte_i) for byte_i in str_split(self.easybyte.b, n)]

    def find_v_key(self, key_l):
        # Given a key length, returns plausible Vigenère keys of that length
        print(f'Searching for repeating key of length {key_l}')
        strips = self.split(key_l)
        keys_by_strip = []

        for strip in strips:
            keys_by_strip.append(strip.single_byte_keys(True, True).keys)

        possibilities = prod([len(keys) for keys in keys_by_strip])
        print(f"Found {possibilities} plausible key(s)")

        self.key_poss = keys_by_strip

    def keys_from_poss(self):
        keys = [sing_byte for sing_byte in self.key_poss[0]]
        for i in range(1, len(self.key_poss)):
            keys = [old_key + new_byte for old_key in keys for new_byte in self.key_poss[i]]

        if len(keys) > 1:
            self.keys = keys

        if len(keys) == 1:
            self.key = keys[0]

        else:
            raise Exception("This shouldn't happen")

    def solve(self):
        # Returns code decyphered according to key
        print(self.easybyte.xor(self.key).convert('text'))

    def freq(self):
        freqs = [0]*256
        for byt in self.easybyte.b:
            # Each byt is an integer representing ord(byte)
            freqs[byt] += 1

        return freqs

    def simple_freq_test(self, lb_max_freq=10):
        freqs = self.freq()

        return max(freqs) > len(self.easybyte.b) / lb_max_freq

class ListVCode:
    def __init__(self, code_file, base=None):
        with open(code_file) as file:
            self.codes = [VCode(line, base) for line in file]

    def detect_single_byte(self):
        for i in range(len(self.codes)):
            code = self.codes[i]
            if code.simple_freq_test():
                print(i)
                code = code.single_byte_keys()
                code.use_keys()

class AESCode:
    def __init__(self, code, base=None):
        self.easybyte = EasyByte(code, base)
        self.cipher = None
        self.iv = None

    def gen_cipher(self, key):
        # Generates cipher according to key
        # May request random key by entering key as the string 'random'
        if key == 'random':
            key = rand_bytes(16)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def ecb_solve(self, letsunpad=True):
        ans = self.cipher.decrypt(self.easybyte.b)

        # Unpad removes padding originally added to make the message a multiple of 128 bits
        if letsunpad:
            ans = unpad(ans, AES.block_size)

        print(ans.decode())
        return ans.decode()

    def block_list(self):
        blen = len(self.easybyte.b)
        assert blen % 16 == 0
        nblocks = blen//16
        return [EasyByte(self.easybyte.b[16*i:16*i + 16]) for i in range(nblocks)]

    def repeat(self):
        count = 0
        blocks = self.block_list()
        for i in range(len(blocks) - 1):
            for j in range(i + 1, len(blocks)):
                if blocks[i].b == blocks[j].b:
                    count += 1
        return count

    def ecb_encrypt(self, key, padding=True):
        cipher = AES.new(key, AES.MODE_ECB)
        if padding:
            self.easybyte.b = pad(self.easybyte.b, AES.block_size)
        new = AESCode(cipher.encrypt(self.easybyte.b))
        new.cipher = cipher
        return new

    def cbc_encrypt(self, key, iv):
        self.gen_cipher(key)
        self.iv = iv
        self.easybyte.b = pad(self.easybyte.b, AES.block_size)  # pad
        blocks = self.block_list()
        prev_cipher_block = iv
        gibberish = b''
        for i in range(len(blocks)):
            new_easybyte = blocks[i].xor(prev_cipher_block)
            new_code = self.cipher.encrypt(new_easybyte.b)
            gibberish += new_code
            prev_cipher_block = new_code
        self.easybyte = EasyByte(gibberish)
        return self

    def cbc_solve(self):
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
        print(sol.decode())
        return sol.decode()

class ListECB:
    def __init__(self, code_file, base=None):
        with open(code_file) as file:
            self.codes = [AESCode(line, base) for line in file]

    def simple_repeat_test(self):
        for k in range(len(self.codes)):
            repeat_k = self.codes[k].repeat()
            if repeat_k != 0:
                print(f'Code {k} has {repeat_k} repeats')
