# Challenge 1-8:
# Detect AES in ECB mode

from Cryptopals_main import ListECB

def main():
    # Simply scours each line in the challenge text for repeated blocks
    # Lines with many blocks are likely encrypted in ECB mode
    c1_8 = ListECB('../Challenge_1-8.txt', 'hex')
    c1_8.simple_repeat_test()


if __name__ == "__main__":
    main()
