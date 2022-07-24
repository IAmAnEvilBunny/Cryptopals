# Challenge 2-8
# CBC bitflipping attacks

from Cryptopals_main import AESCode, EasyByte, gen_sandwich

def main():
    # String function for the challenge
    c2_8_str_fun = gen_sandwich(b"comment1=cooking%20MCs;userdata=",
                                b";comment2=%20like%20a%20pound%20of%20bacon",
                                b";=")

    # Create random oracle
    c2_8 = AESCode(key='random', iv='random')
    c2_8_oracle = c2_8.gen_cbc_oracle(c2_8_str_fun)

    # Pass an empty block (that we don't mind scrambling) followed by block we wish to modify
    # Flip bits in the empty blocks, this scrambles the block and flips bits in the next when decoding
    c2_8.easybyte = EasyByte(
        c2_8_oracle(b'\x00' * 16 + b':admin<true:' + b'\x00' * 4))\
        .bit_flip([32, 38, 43])

    # Solve
    assert b';admin=true;' in c2_8.cbc_solve()
    print('Challenge 2-8 passed !')


if __name__ == "__main__":
    main()
