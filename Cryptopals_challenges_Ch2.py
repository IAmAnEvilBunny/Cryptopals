from Cryptopals_main import *

## Challenge 2-1
# Padding and unpadding implemented

## Challenge 2-2
C2_10 = AESCode('Challenge_2-10.txt', 'b64')
C2_10.gen_cipher(b'YELLOW SUBMARINE')
C2_10.iv = b'\x00'*16
C2_10.cbc_solve()

## Challenge 2-4
C2_12 = AESCode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                'YnkK', 'b64').ecb_encrypt('random')

C2_12_oracle = ECBOracle(C2_12.oracle_fun)
C2_12_oracle.solve()

## Challenge 2-5
basic_profile_string = Profile('foo@baz').p
C2_5 = AESCode(basic_profile_string, 'text')
C2_5.cbc_encrypt('random', b'0123456789abcdef')
print(string_to_dict(C2_5.cbc_solve()))

## Challenge 2-6
C2_6 = AESCode(basic_profile_string, 'text', True).ecb_encrypt('random')
C2_6.prep = b'Yo1230123456789abcde'
C2_6_oracle = ECBOracle(C2_6.oracle_fun)
print(C2_6_oracle.l_full_prep_blocks)
C2_6_oracle.solve()
