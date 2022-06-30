from Cryptopals_main import *

## Challenge 1-1
# Declare byte
C1_1 = EasyByte('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d',
                'hex')

# Check conversion is correct
assert C1_1.convert('b64') == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

# If correct, print success:
print(f"1.1 passed !\nhex:\n"
      f"{C1_1.convert('hex')}\nto base64 is:\n"
      f"{C1_1.convert('b64')}")

## Challenge 1-2
# Write a function that takes two equal-length buffers and produces their XOR combination.
C1_2 = EasyByte('1c0111001f010100061a024b53535009181c', 'hex')
xoredC1_2 = C1_2.xor('686974207468652062756c6c277320657965', 'hex')

assert xoredC1_2.convert('hex') == '746865206b696420646f6e277420706c6179'

print(f"1.2 passed !\n\n"
      f"1c0111001f010100061a024b53535009181c\nXORed with\n"
      f"686974207468652062756c6c277320657965\nis\n"
      f"746865206b696420646f6e277420706c6179\n\n"
      f"which decoded to text is:\n"
      f"{xoredC1_2.convert('text')}")

## Challenge 1_3
# Single-byte XOR cipher
C1_3 = VCode('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 'hex')
print(f"Challenge 1.3: XORing\n"
      f"{C1_3.easybyte.convert('hex')}\n"
      f"against all 256 repreating single byte keys,\n"
      f"and filtering for intelligible English yields:\n")
C1_3.single_byte_keys(True, True)
C1_3.use_keys()

## Challenge 1-4
# Detect single-character XOR
C1_4 = ListVCode('Challenge_1-4.txt', 'hex')
print('The following lines in the file pass a simple frequency test,\n'
      'decryption follows the line number if the line is indeed XORed\n'
      'against a single byte repreating key.')
C1_4.detect_single_byte()

## Challenge 1-5
# Implement repeating-key XOR
C1_5 = VCode("Burning 'em, if you ain't quick and nimble\n"
             "I go crazy when I hear a cymbal", 'text')
C1_5_key = 'ICE'
C1_5_encrypted = C1_5.easybyte.xor(C1_5_key, 'text').convert('hex')

assert C1_5_encrypted == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262' \
                         '26324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c69' \
                         '2b20283165286326302e27282f'

print(f'1.5 passed !\n'
      f'The text:\n'
      f"{C1_5.easybyte.convert('text')}\n\n"
      f"when XORed against 'ICE', gives (in hex):\n"
      f"{C1_5_encrypted}")

## Challenge 1-6
# Break repeating-key XOR
# Part 1: Hamming
C1_6_text1 = 'this is a test'
C1_6_text2 = 'wokka wokka!!!'
C1_6_ham_ans = 37
assert EasyByte(C1_6_text1, 'text').hamming(C1_6_text2, 'text') == C1_6_ham_ans

print(f"The Hamming distance between '{C1_6_text1}' and '{C1_6_text2}'\n"
      f"is {C1_6_ham_ans} as required.")

## Challenge 1-6, part 2: key lengths

C1_6 = VCode('Challenge_1-6.txt', 'b64')
C1_6.key_length(10)
# 5, 15 and 29 seem good

## Challenge 1-6, part 3: find key
C1_6_key_l = 29

C_1_6_key = C1_6.find_v_key(29)
C1_6.keys_from_poss()

## Challenge 1-6: answer
C1_6.solve()

## Challenge 1-7:
C1_7 = AESCode('Challenge_1-7.txt', 'b64')
C1_7.gen_cipher(b'YELLOW SUBMARINE')
C1_7.ecb_solve()

## Challenge 1-8:
C1_8 = ListECB('Challenge_1-8.txt', 'hex')
C1_8.simple_repeat_test()
