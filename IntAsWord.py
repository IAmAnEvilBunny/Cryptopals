"""
IntAsWord class for bitwise operations on words represented as integers.
"""

# Functions for class IntAsWord
# Conversions
def binary(n, w=8, scale=10):
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
    w : int, optional
        Number of bits to be returned (default is 8)

    Returns
    -------
    str
        Byte
    """
    if type(n) == int:
        n = str(n)
    assert 0 <= int(n, scale) < 2 ** w  # So that integer may be written as m bits
    return bin(int(n, scale))[2:].zfill(w)

# Words as lists of 0s and 1s
def str_to_int_lst(int_str):
    # Takes a string representing an integer
    # Returns a list with one digit per entry
    lst = []
    for char in int_str:
        lst.append(int(char))

    return lst

def bin_lst_to_int(lst):
    # Takes a list where each entry represents a bit
    # Returns an integer
    lst = [str(i) for i in lst]
    as_int = int(''.join(lst), 2)
    return as_int

# Word manipulation class
class IntAsWord:
    """Class for the manipulation of words of a certain length.
    Initiated from an integer.
    Ex: The length-3 word 010 represents 2.

    Attributes
    ----------
    as_int: int
        Integer the words represents
    w: int
        Length of the word
    bin: str
        Word represented as a string (Ex: '010')

    Parameters
    ----------
    int_byte: int
        Integer the words represents
    w: int
        Length of the word
        """
    def __init__(self, int_byte: int, w: int):
        self.as_int = int_byte
        self.w = w
        self.bin = str_to_int_lst(binary(int_byte, w))

    # Properties
    def bin_trailing_zeroes(self):
        # Returns the number of trailing zeroes of the byte in binary format
        # Ex: 01011000 has 3 trailing zeroes
        counter = 0
        for i in reversed(range(len(self.bin))):
            if self.bin[i] == 0:
                counter += 1
            else:
                break

        return counter

    # Operations
    def lrot(self, n: int):
        # Left rotate bits by n positions
        m = n % self.w  # The operation is congruent modulo the length of the word
        bin_str = binary(self.as_int, self.w)  # Obtain integer as binary string
        bin_str = bin_str[m: self.w] + bin_str[0: m]  # Perform rotation

        return IntAsWord(int(bin_str, 2), self.w)

    # Inversions
    def invert_x_rshift_a_xor_x(self, a):
        # Solve self.as_int = x ^ (x >> a) for x
        if 2*a < self.w:
            raise Exception('Not one to one')

        else:
            return IntAsWord(self.as_int ^ (self.as_int >> a), self.w)

    def invert_x_lshift_a_and_b_xor_x(self, a, b):
        # Solve self.as_int = x ^ ((x<<a) & b) for x
        a = IntAsWord(a, self.w)
        b = IntAsWord(b, self.w)

        # Get answer as list of bits
        ans = list([None] * self.w)  # type: list

        # Since x<<a is zero in the last a positions, we can solve for those positions:
        for i in range(self.w - a.as_int, self.w):
            ans[i] = self.bin[i] ^ 0

        # From x_{i + a} we may obtain x_{i} and so we solve iteratively
        for i in reversed(range(self.w - a.as_int)):
            ans[i] = self.bin[i] ^ (ans[i + a.as_int] & b.bin[i])

        # Process answer into IntAsWord
        ans = bin_lst_to_int(ans)  # type: int
        ans = IntAsWord(ans, self.w)  # type: IntAsWord

        return ans

    def invert_x_rshift_a_and_b_xor_x(self, a, b):
        # Solve self.as_int = x ^ ((x>>a) & b) for x
        a = IntAsWord(a, self.w)
        b = IntAsWord(b, self.w)

        # Get answer as list of bits
        ans = [None] * self.w  # type: list

        # Since x>>a is zero in the first a positions, we can solve for those positions:
        for i in range(a.as_int):
            ans[i] = self.bin[i] ^ 0

        # From x_{i} we may obtain x_{i + a} and so we solve iteratively
        for i in range(a.as_int, self.w):
            ans[i] = self.bin[i] ^ (ans[i - a.as_int] & b.bin[i])

        # Process answer into IntAsWord
        ans = bin_lst_to_int(ans)  # type: int
        ans = IntAsWord(ans, self.w)  # type: IntAsWord

        return ans
