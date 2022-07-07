from Cryptopals_main import *

## Challenge 3-1
def challenge_3_1():

    # Randomly encrypt a random string from Challenge_3-17.txt
    c3_1 = AESCode(key='random', iv='random')  # Random cipher

    # Create function that randomly returns a string from Challenge_3-17.txt as a byte
    c3_1_rand_byte_fun = create_rand_byte_fun('Challenge_3-17.txt', 'b64')

    # Create oracle out of random cipher and byte generator
    c3_1_oracle = c3_1.gen_cbc_oracle_rand(c3_1_rand_byte_fun)

    # See example generation
    c3_1.easybyte.b = c3_1_oracle()
    print(c3_1.easybyte.b)

    # As in previous challenges, AESCode.cbc_solve solves the cipher and attempts to unpad
    # An error will be raised if unpadding runs into a problem (ex: incorrect padding)
    c3_1.cbc_solve()


challenge_3_1()

## Challenge 3-2
def challenge_3_2():
    c3_2_ciphertext = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    c3_2 = AESCode(c3_2_ciphertext, 'b64', key=b'YELLOW SUBMARINE', nonce=empty_bytes(8))
    print(c3_2.ctr())

    
challenge_3_2()

## Challenge 3-4
def challenge_3_4a():
    # Find length of shortest line
    c3_4 = ListVCode('Challenge_3-20.txt', 'b64')
    c3_4.truncate_and_join()


challenge_3_4a()

## Challenge 3-4b
def challenge_3_4b(key_l):
    # Truncate and join, find repeating key of length the shortest line
    c3_4 = ListVCode('Challenge_3-20.txt', 'b64')
    c3_4_code = c3_4.truncate_and_join()
    c3_4_code.find_v_key(key_l)
    print(c3_4_code.key_poss)


challenge_3_4b(53)

## Challenge 3-4c
def challenge_3_4c(key):
    # Solve
    c3_4 = ListVCode('Challenge_3-20.txt', 'b64')
    for code in c3_4.codes:
        code.key = key  # Set key as what we found previously
        code.solve()


challenge_3_4c(b'\x00')
