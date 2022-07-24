## Challenge 2-4
# Byte-at-a-time ECB decryption (Simple)

from EasyByte import EasyByte
from Cryptopals_main import AESCode, DetOracle, gen_sandwich

def main():
    # Record exercises plaintext
    c2_12_plaintext = EasyByte('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                               'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                               'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                               'YnkK', 'b64')

    # Generate random cipher
    c2_12 = AESCode(key='random')

    # Generate random oracle
    c2_12_str_fun = gen_sandwich(app=c2_12_plaintext.b)
    c2_12_oracle = DetOracle(c2_12.gen_ecb_oracle(c2_12_str_fun))

    # Solve
    print(c2_12_oracle.solve().decode())


if __name__ == "__main__":
    main()
