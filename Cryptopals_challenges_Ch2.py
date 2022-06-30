from Cryptopals_main import *

## Challenge 2-1
# Padding and unpadding implemented

## Challenge 2-2
C2_10 = AESCode('Challenge_2-10.txt', 'b64')
C2_10.gen_cipher(b'YELLOW SUBMARINE')
C2_10.iv = b'\x00'*16
C2_10.cbc_solve()