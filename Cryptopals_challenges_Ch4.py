from Cryptopals_main import *

## Challenge 4-2
# CTR bitflipping

def challenge_4_2():
    # String function for the challenge
    c4_2_str_fun = gen_sandwich(b"comment1=cooking%20MCs;userdata=",
                                b";comment2=%20like%20a%20pound%20of%20bacon",
                                b";=")

    # Create random oracle
    c4_2 = AESCode(key='random', nonce=8)  # Has random key and random 8-byte nonce
    c4_2_oracle = c4_2.gen_ctr_oracle(c4_2_str_fun)

    # Simply flip the bits in the ciphertext corresponding to those we wish to flip
    # in the plain text
    c4_2.easybyte = EasyByte(
            c4_2_oracle(b':admin<true:'))\
        .bit_flip([32, 38, 43])

    # Check we have desired result
    assert b';admin=true;' in c4_2.ctr().easybyte.b
    print('Challenge 4-2 passed !')


challenge_4_2()
