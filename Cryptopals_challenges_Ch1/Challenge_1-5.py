# Challenge 1-5
# Implement repeating-key XOR

from Cryptopals_main import VCode

def main():
    # Declare VCode, passing text we wish to encrypt
    c1_5 = VCode("Burning 'em, if you ain't quick and nimble\n"
                 "I go crazy when I hear a cymbal", 'text')

    c1_5_key = 'ICE'  # Declare key
    c1_5_encrypted = c1_5.easybyte.xor(c1_5_key, 'text').convert('hex')  # XOR against key

    # Ensure we have expected result
    assert c1_5_encrypted == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262' \
                             '26324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c69' \
                             '2b20283165286326302e27282f'

    # Print success
    print(f'1.5 passed !\n'
          f'The text:\n'
          f"{c1_5.easybyte.convert('text')}\n\n"
          f"when XORed against 'IcE', gives (in hex):\n"
          f"{c1_5_encrypted}")


if __name__ == "__main__":
    main()
