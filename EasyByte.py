"""
EasyByte class for easy manipulation of byte strings
@author: Lawrence Arscott
"""

##
from base64 import b64encode, b64decode
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

def binary(n, scale, m=8):
    """
    Converts integer n base scale to m bits (default, m=8 for a byte)
    n may be a string or an integer

    Parameters
    ----------
    n : str or int
        Integer to be converted (must be between 0 and 255)
        Given as a str in some base
    scale : int
        Base to which n is to be taken
    m : int, optional
        Number of bits to be returned (default is 8)

    Returns
    -------
    str
        Byte
    """
    if type(n) == int:
        n = str(n)
    assert 0 <= int(n, scale) < 2**m  # So that integer may be written as m bits
    return bin(int(n, scale))[2:].zfill(m)

# Text formatting
def strtotwos(s: str, n=2):
    # Splits string into list of strings of length 2
    return [s[i:i+n] for i in range(0, len(s), n)]

def resize_key(key, n):
    # Resize key to length n by repeating
    new_key = key * (n // len(key) + 1)

    return new_key[:n]  # Chop off excess

def single_line_read(txtfile: str):
    # Reads file as a single line (stripping newlines)
    with open(txtfile) as file:
        sngl_line = ''.join([line.rstrip('\n') for line in file])
    return sngl_line

# Class
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
            return EasyByte.make_byte(self, single_line_read(code), base)

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
