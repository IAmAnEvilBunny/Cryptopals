## Challenge 2-6
# Byte-at-a-time ECB decryption (Harder)

from Cryptopals_main import Profile, AESCode, DetOracle, rand_bytes, randint, gen_sandwich
from EasyByte import EasyByte

def main():
    # setup
    basic_profile_string = Profile(b'foo@baz').p  # Create a profile
    c2_6_prep = rand_bytes(randint(1, 32))  # Declare random prepended string
    c2_6_app = EasyByte(basic_profile_string, 'text').b  # Profile to be decoded
    c2_6b_fun = gen_sandwich(c2_6_prep, c2_6_app)  # Generate string manipulator for oracle

    c2_6b = AESCode(key='random')  # Generate random cipher
    c2_6b_oracle = DetOracle(c2_6b.gen_ecb_oracle(c2_6b_fun))  # Declare oracle

    # solve
    print(c2_6b_oracle.solve().decode())


if __name__ == "__main__":
    main()
