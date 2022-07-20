"""
Implementation of the pseudocode for the MT19937 random number generator, found at
https://en.wikipedia.org/wiki/Mersenne_Twister#k-distribution

IntAsWord class is used for easy manipulation of words and their operations.
Particularly useful for inverting certain operations of the RNG.

@author: Lawrence Arscott
"""

##
from random import randint
from IntAsWord import IntAsWord

# Operations
def bit_not(n, numbits=8):
    # Returns not n, where n is a 'numbits' bits integer
    return (1 << numbits) - 1 - n

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

        return y.as_int

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
