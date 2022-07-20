from EasyByte import EasyByte
from Cryptopals_main import VCode

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

C_1_6 = C1_6.find_v_key(29)
C1_6.keys_from_poss()

## Challenge 1-6: answer
C1_6.solve()
