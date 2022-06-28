from Cryptopals1v2 import *

## Challenge 1-1
C1_1 = EasyByte('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d',
                'hex')
print(C1_1.convert('b64'))

## Challenge 1-2
# Write a function that takes two equal-length buffers and produces their XOR combination.
C1_2 = EasyByte('1c0111001f010100061a024b53535009181c', 'hex')
xoredC1_2 = C1_2.xor('686974207468652062756c6c277320657965', 'hex')

assert xoredC1_2.convert('hex') == '746865206b696420646f6e277420706c6179'
print(xoredC1_2.convert('text'))

## Challenge 1_3
# Single-byte XOR cipher
C1_3 = VCode('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 'hex')
VCode.single_byte_keys(C1_3, True, True)

## Challenge 1-4
# Detect single-character XOR
C1_4 = ListVCode('Challenge_1-4.txt', 'hex')
print(C1_4.codes[0].easybyte.convert('hex'))
C1_4.detect_single_byte()
## Challenge 1-5
# Implement repeating-key XOR
C1_5 = VCode("Burning 'em, if you ain't quick and nimble\n"
             "I go crazy when I hear a cymbal", 'text')

print(C1_5.easybyte.xor('ICE', 'text').convert('hex'))
## Challenge 1-6
# Break repeating-key XOR
# Part 1: Hamming
assert EasyByte('this is a test', 'text').hamming('wokka wokka!!!', 'text') == 37


## Challenge 1-6, part 2: key lengths

C1_6 = VCode('Challenge_1-6.txt', 'b64')
C1_6.key_length(10)
# 5, 15 and 29 seem good

## Challenge 1-6, part 3: find key
C_1_6_key = C1_6.find_v_key(29)
C1_6.keys_from_poss()


## Challenge 1-6: answer
C1_6.solve()

## Challenge 1-7:
C1_7 = ECBCode('Challenge_1-7.txt', 'b64')
C1_7.gen_cipher(b'YELLOW SUBMARINE')
C1_7.solve()

## Challenge 1-8:
C1_8 = ListECB('Challenge_1-8.txt', 'hex')
C1_8.simple_repeat_test()
