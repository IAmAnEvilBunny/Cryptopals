# Challenge 3-5
# Implement the MT19937 Mersenne Twister RNG

from MT19937 import MT19937

def main(seed):
    print(MT19937(seed).rand_num_gen())


if __name__ == "__main__":
    main(321)
