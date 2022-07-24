## Challenge 2-5
#

from Cryptopals_main import AESCode, Profile, DetOracle, string_to_dict, user_profile_for

def main():
    basic_profile_string = Profile(b'foo@baz').p  # Create a profile
    c2_5 = AESCode(basic_profile_string, 'text', key='random')  # ecb encrypt it
    c2_5.ecb_encrypt()
    print(string_to_dict(c2_5.ecb_solve().decode()))  # decrypt it

    # b) Generate oracle using user profile as the string function
    c2_5b = AESCode(key='random')
    c2_5b_oracle = DetOracle(c2_5b.gen_ecb_oracle(user_profile_for))

    # Solve the challenge: modify email and cipher text to get an admin profile
    c2_5b.easybyte.b = c2_5b_oracle.challenge2_5()
    print(c2_5b.ecb_solve())


if __name__ == "__main__":
    main()
