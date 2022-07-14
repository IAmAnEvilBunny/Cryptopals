"""
Implementation of the pseudocode for the MT19937 random number generator, found at
https://en.wikipedia.org/wiki/Mersenne_Twister#k-distribution

IntAsWord class is used for easy manipulation of words and their operations.
Particularly useful for inverting certain operations of the RNG.

@author: Lawrence Arscott
"""

##
from random import randint

# MT19937 RNG
class MT19937:
    # MT19937 RNG
    # Implementation of the pseudocode found at
    # https://en.wikipedia.org/wiki/Mersenne_Twister#k-distribution
    def __init__(self, seed=None):
        # Parameters
        (self.w, self.n, self.m, self.r) = (32, 624, 397, 31)
        self.a = int('9908b0df', 16)
        (self.u, self.d) = (11, int('ffffffff', 16))
        (self.s, self.b) = (7, int('9d2c5680', 16))
        (self.t, self.c) = (15, int('efc60000', 16))
        self.wiki_l = 18
        self.f = 1812433253

        # Seed
        self.seed = seed if seed else randint(1, 2 ** self.w - 1)

        # Random number generation
        self.index = 0
        self.mt = [0]
        self.rand_num_gen = self.mt19937()

    def mt19937(self):
        # https://en.wikipedia.org/wiki/Mersenne_Twister#k-distribution
        lower_mask = (1 << self.r) - 1  # That is, the binary number of r 1's or 2**r - 1
        upper_mask = bit_not(lower_mask, 32)
        self.index = self.n

        # Initialise the generator from a seed
        def seed_mt():
            self.mt = [0] * self.n
            self.mt[0] = self.seed
            for i in range(1, self.n):
                self.mt[i] = (self.f * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))) + i) \
                             % 2 ** self.w

        seed_mt()

        def extract_number():
            if self.index == self.n:
                twist()

            y = self.mt[self.index]

            # Tempering step
            y = self.temper(y)

            self.index += 1

            return y % 2 ** self.w

        def twist():
            for i in range(self.n):
                x = (self.mt[i] & upper_mask) + (self.mt[(i + 1) % self.n] & lower_mask)
                xa = x >> 1
                if (x % 2) != 0:  # lowest bit of x is 1
                    xa = xa ^ self.a
                self.mt[i] = self.mt[(i + self.m) % self.n] ^ xa

            self.index = 0

        return extract_number

    def temper(self, y):
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.wiki_l)

        return y

    def untemper(self, output):
        y = IntAsWord(output, self.w)

        y = y.invert_x_rshift_a_xor_x(self.wiki_l)
        y = y.invert_x_lshift_a_and_b_xor_x(self.t, self.c)
        y = y.invert_x_lshift_a_and_b_xor_x(self.s, self.b)
        y = y.invert_x_rshift_a_and_b_xor_x(self.u, self.d)

        return y.int_b

    def clone(self, rng_fun):
        # Given self.n outputs, clones the RNG

        # Extract the mt from self.n outputs
        n_outputs = [rng_fun() for _ in range(self.n)]  # '_' signifies we don't care about the value
        cloned_mt = [self.untemper(val) for val in n_outputs]

        # Initiate clone as an RNG with the same parameters
        clone = MT19937()
        clone.seed = f'RNG clone'

        # Clone the mt without requiring the original seed
        clone.mt = cloned_mt
        clone.index = 0  # The values we obtained are post twist

        return clone

    def stream(self, n_bytes: int = 1):
        # Generates a stream of random bytes based on the RNG

        stock = b''  # A stock of random bytes enabling us not to hold all random bytes in memory

        while True:
            # Replenish stock if not enough
            if len(stock) < n_bytes:
                rand_int = self.rand_num_gen()  # Obtain a new random 32-bit int from the RNG
                stock += rand_int.to_bytes(4, byteorder='big')  # Convert to 4 bytes and add to stock

            yield stock[:n_bytes]  # yield desired bytes

            stock = stock[n_bytes:]  # Remove 'used up' bytes

# Functions for class IntAsWord
# Conversions
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

# Operations
def bit_not(n, numbits=8):
    # Returns not n, where n is a 'numbits' bits integer
    # https://stackoverflow.com/questions/31151107/how-do-i-do-a-bitwise-not-operation-in-python
    return (1 << numbits) - 1 - n

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
    int_b: int
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
        self.int_b = int_byte
        self.w = w
        self.bin = str_to_int_lst(binary(int_byte, 10, w))

    # Properties
    def bin_trailing_zeroes(self):
        # Returns the number of trailing zeroes of the byte in binary format
        # Ex: 01011000 has 3 trailing zeroes
        counter = 0
        for i in reversed(range(len(self.bin))):
            if self.bin[i] == '0':
                counter += 1
            else:
                break

        return counter

    # Inversions
    def invert_x_rshift_a_xor_x(self, a):
        # Solve self.int_b = x ^ (x >> a) for x
        if 2*a < self.w:
            raise Exception('Not one to one')

        else:
            return IntAsWord(self.int_b ^ (self.int_b >> a), self.w)

    def invert_x_lshift_a_and_b_xor_x(self, a, b):
        # Solve self.int_b = x ^ ((x<<a) & b) for x
        a = IntAsWord(a, self.w)
        b = IntAsWord(b, self.w)

        # Get answer as list of bits
        ans = list([None] * self.w)  # type: list

        # Since x<<a is zero in the last a positions, we can solve for those positions:
        for i in range(self.w - a.int_b, self.w):
            ans[i] = self.bin[i] ^ 0

        # From x_{i + a} we may obtain x_{i} and so we solve iteratively
        for i in reversed(range(self.w - a.int_b)):
            ans[i] = self.bin[i] ^ (ans[i + a.int_b] & b.bin[i])

        # Process answer into IntAsWord
        ans = bin_lst_to_int(ans)  # type: int
        ans = IntAsWord(ans, self.w)  # type: IntAsWord

        return ans

    def invert_x_rshift_a_and_b_xor_x(self, a, b):
        # Solve self.int_b = x ^ ((x>>a) & b) for x
        a = IntAsWord(a, self.w)
        b = IntAsWord(b, self.w)

        # Get answer as list of bits
        ans = [None] * self.w  # type: list

        # Since x>>a is zero in the first a positions, we can solve for those positions:
        for i in range(a.int_b):
            ans[i] = self.bin[i] ^ 0

        # From x_{i} we may obtain x_{i + a} and so we solve iteratively
        for i in range(a.int_b, self.w):
            ans[i] = self.bin[i] ^ (ans[i - a.int_b] & b.bin[i])

        # Process answer into IntAsWord
        ans = bin_lst_to_int(ans)  # type: int
        ans = IntAsWord(ans, self.w)  # type: IntAsWord

        return ans
