## Challenge 3-7
# Clone an MT19937 RNG from its output

from MT19937 import MT19937

def clone(seed: int):
    # Creates and clones MT19937 RNG given a seed
    c3_7_rng = MT19937(seed)
    c3_7_clone = MT19937()

    return c3_7_clone.clone(c3_7_rng.rand_num_gen)

def main(seed: int, n: int):
    # Checks the clone gives the same output as the original in the first n trials
    c3_7_original = MT19937(seed)
    c3_7_clone = clone(seed)

    # Check the first n outputs match
    for i in range(n):
        assert c3_7_original.rand_num_gen() == c3_7_clone.rand_num_gen()

    # Print success
    print(f'Clone appears to work based on {n} trials')


if __name__ == "__main__":
    main(234, 1000)
