## Challenge 2-1
# Padding and unpadding implemented

## Challenge 2-2
C2_10 = AESCode('Challenge_2-10.txt', 'b64', b'YELLOW SUBMARINE', b'\x00'*16)
C2_10.cbc_solve()

## Challenge 2-4
# Record exercises plaintext
C2_12_plaintext = EasyByte('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                           'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                           'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                           'YnkK', 'b64')

# Generate random cipher
C2_12 = AESCode(key='random')

# Generate challenge's string function
C2_12_str_fun = gen_sandwich(app=C2_12_plaintext.b)

# Generate random oracle
C2_12_oracle = DetOracle(C2_12.gen_ecb_oracle(C2_12_str_fun))

# Solve
C2_12_oracle.solve()

## Challenge 2-5
basic_profile_string = Profile(b'foo@baz').p  # Create a profile
C2_5 = AESCode(basic_profile_string, 'text', key='random')  # ecb encrypt it
C2_5.ecb_encrypt()
print(string_to_dict(C2_5.ecb_solve()))  # decrypt it

# b) Generate oracle using user profile as the string function
C2_5b = AESCode(key='random')
C2_5b_oracle = DetOracle(C2_5b.gen_ecb_oracle(user_profile_for))

# Solve the challenge: modify email and cipher text to get an admin profile
C2_5b.easybyte.b = C2_5b_oracle.challenge2_5()
print(C2_5b.ecb_solve())

## Challenge 2-6
# setup
C2_6_prep = rand_bytes(randint(1, 32))  # Declare random prepended string
C2_6_app = EasyByte(basic_profile_string, 'text').b  # Profile to be decoded
C2_6b_fun = gen_sandwich(C2_6_prep, C2_6_app)  # Generate string manipulator for oracle

C2_6b = AESCode(key='random', iv='random')  # Generate random cipher
C2_6b_oracle = DetOracle(C2_6b.gen_ecb_oracle(C2_6b_fun))  # Declare oracle

# solve
C2_6b_oracle.solve()


## Challenge 2-7
# Already implemented

## Challenge 2-8
def challenge_2_8():
    # String function for the challenge
    c2_8_str_fun = gen_sandwich(b"comment1=cooking%20MCs;userdata=",
                                b";comment2=%20like%20a%20pound%20of%20bacon",
                                b";=")

    # Create random oracle
    c2_8 = AESCode(key='random', iv='random')
    c2_8_oracle = c2_8.gen_cbc_oracle(c2_8_str_fun)

    # Pass an empty block (that we don't mind scrambling) followed by block we wish to modify
    encoded = c2_8_oracle(b'\x00' * 16 + b':admin<true:' + b'\x00' * 4)
    # Flip bits in the empty blocks, this scrambles the block and flips bits in the next when decoding
    flipped = bit_flip(encoded, [32, 38, 43])

    # Pass onto random cipher and solve
    c2_8.easybyte.b = flipped
    assert b';admin=true;' in c2_8.cbc_solve()
    print('Challenge 2-8 passed !')


challenge_2_8()
