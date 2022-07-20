# Challenge 1-4
# Detect single-character XOR

from Cryptopals_main import ListVCode

def main():
    c1_4 = ListVCode('../Challenge_1-4.txt', 'hex')
    print('The following lines in the file pass a simple frequency test,\n'
          'decryption follows the line number if the line is indeed XORed\n'
          'against a single byte repreating key.')
    c1_4.detect_single_byte()


if __name__ == "__main__":
    main()
