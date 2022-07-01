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

break_repeating(C2_12.oracle)

## Challenge 2-5
C2_5 = AESCode(Profile('foo@baz').p, 'text')
C2_5.cbc_encrypt('random', b'0123456789abcdef')
print(string_to_dict(C2_5.cbc_solve()))
