## Challenge 3-4
# Break fixed-nonce CTR statistically

from Cryptopals_main import ListVCode

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
